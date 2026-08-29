// Package decoder turns received datagrams into normalized flow records.
// This file holds the per-datagram dispatch and the decode accounting.
package decoder

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// Decode error reasons published in the reason label. They are a closed set:
// a new failure mode gets a constant here rather than a free-form string, so
// the label stays bounded.
const (
	// ReasonUnsupportedVersion marks a datagram no decoder claims.
	ReasonUnsupportedVersion = "unsupported_version"
	// ReasonMalformed marks a datagram whose claimed structure does not fit
	// its bytes.
	ReasonMalformed = "malformed"
	// ReasonUnsupportedAggregation marks a NetFlow v8 datagram whose
	// aggregation method this exporter does not know.
	ReasonUnsupportedAggregation = "unsupported_aggregation"
	// ReasonMissingTemplate marks a data flowset whose template has not
	// arrived, which is expected after a restart until the device
	// re-announces its templates.
	ReasonMissingTemplate = "missing_template"
	// ReasonInvalidTemplate marks a template announcement this exporter
	// refuses: a zero-width field, a field count past the limit, or a
	// specifier that does not fit its flowset.
	ReasonInvalidTemplate = "invalid_template"
	// ReasonReservedSet marks a set id its protocol leaves unassigned:
	// 2-255 in v9; 0, 1 and 4-255 in IPFIX. Using one is a dialect this
	// exporter does not speak.
	ReasonReservedSet = "reserved_set"
	// ReasonDomainLimit marks a datagram whose observation domain the
	// exporter refused, the device being at its domain budget.
	ReasonDomainLimit = "domain_limit"
)

// decodeError carries the reason a datagram was rejected, for the error
// counter, and the detail, for the debug log.
type decodeError struct {
	reason string
	detail string
}

// Error implements the error interface.
func (e *decodeError) Error() string {
	return e.reason + ": " + e.detail
}

// Reason returns the reason label value.
func (e *decodeError) Reason() string {
	return e.reason
}

// malformed builds the rejection for a structurally broken datagram.
func malformed(format string, args ...any) *decodeError {
	return &decodeError{reason: ReasonMalformed, detail: fmt.Sprintf(format, args...)}
}

// minVersionBytes is what a version sniff needs.
const minVersionBytes = 4

// Wire version numbers as they appear in the first header field.
const (
	wireNetFlowV5 = 5
	wireNetFlowV8 = 8
	wireNetFlowV9 = 9
	wireIPFIX     = 10
	wireSFlowV5   = 5
)

// Decoder dispatches datagrams to the protocol parsers and accounts every
// outcome. One Decoder serves every worker: the NetFlow v5 and v8 parsers
// hold no state, and the template store, the application tables, the
// interner and the statistics are all concurrency-safe.
type Decoder struct {
	stats     *Stats
	templates *templateStore
	apps      *appTables
	strings   *interner
	// now stamps the decode accounting and the exporter idle-sweep cutoff; a
	// test pins it. Flow times are never taken from it: those come from the
	// datagram.
	now func() time.Time
}

// New creates a decoder enforcing the given parser limits.
func New(cfg config.Parser) *Decoder {
	// One interner serves both the per-record strings and the tables the
	// options templates announce, so a name announced once and carried a
	// million times is stored once and validated in one place.
	intern := newInterner()

	return &Decoder{
		stats:     newStats(),
		templates: newTemplateStore(cfg),
		apps:      newAppTables(intern),
		strings:   intern,
		now:       time.Now,
	}
}

// resolveApplication fills the application strings from the exporter's own
// announcements. A vendor-carried inline name wins, and an identifier the
// table cannot name stays numbered rather than being guessed.
func (d *Decoder) resolveApplication(exporter netip.Addr, r *flow.Record) {
	if r.AppID == 0 || r.AppName != "" {
		return
	}
	r.AppName, r.AppCategory = d.apps.resolve(exporter, r.AppID)
}

// SweepDomains drops the observation domains idle past the template TTL,
// returning their slots to each exporter's budget.
func (d *Decoder) SweepDomains() int {
	return d.templates.sweep()
}

// SweepExporters drops the devices silent past the template TTL, but only
// once the exporter budget is reached.
func (d *Decoder) SweepExporters() int {
	return d.stats.sweepIdle(d.now().Add(-d.templates.ttl).UnixNano())
}

// ExportersRefused reports how many datagrams the exporter budget left
// unattributed. One refused device sending steadily counts once per datagram,
// so this follows that traffic rather than the device count.
func (d *Decoder) ExportersRefused() uint64 {
	return d.stats.refusedCount()
}

// DomainsRefused reports how many datagrams named a domain the per-exporter
// budget turned away, each one discarded whole rather than decoded. One
// refused domain named steadily counts once per datagram, so this follows that
// loss rather than the domain count.
func (d *Decoder) DomainsRefused() uint64 {
	return d.templates.refused()
}

// VendorStringsRefused reports how many exported string fields the interner
// refused as unrepresentable. The refusal precedes its map, so one such name
// counts once per field carrying it rather than once. A refused application
// name leaves the record falling back to its numbered applicationId, to its
// port name, or to no application series at all; a refused category costs
// nothing published, no series carrying one.
func (d *Decoder) VendorStringsRefused() uint64 {
	return d.strings.refusedCount()
}

// ApplicationsRefused reports how many application announcements the
// per-exporter budget turned away, each one an application that stays
// numbered rather than named.
func (d *Decoder) ApplicationsRefused() uint64 {
	return d.apps.refusedCount()
}

// Domains returns the per-observation-domain state for the metrics collector.
func (d *Decoder) Domains() []DomainSnapshot {
	return d.templates.snapshot()
}

// Stats returns the decode statistics for the metrics collector.
func (d *Decoder) Stats() *Stats {
	return d.stats
}

// Decode parses one datagram and appends its flow records to dst, returning
// the extended slice. The outcome is accounted either way, so the returned
// error is for the debug log alone.
func (d *Decoder) Decode(exporter netip.Addr, payload []byte, dst []flow.Record) ([]flow.Record, error) {
	// The device is resolved once, before anything is parsed, and every
	// accounting call below writes through that one resolution. A refusal is
	// counted at the resolution, and a v9 datagram carries an accounting call
	// per flowset, so resolving per call would let a sender set the increment
	// by the number of flowsets it chose to pack.
	at := d.now()
	es := d.stats.exporter(exporter, at)

	version, err := sniffVersion(payload)
	if err != nil {
		es.countError(flow.VersionUnknown, err.Reason())
		return dst, err
	}

	before := len(dst)
	dst, err = d.decodeVersion(version, exporter, es, payload, dst)
	if err != nil {
		es.countError(version, err.Reason())
		return dst[:before], err
	}

	es.countFlows(version, len(dst)-before, at)
	return dst, nil
}

// decodeVersion routes one sniffed datagram to its parser.
func (d *Decoder) decodeVersion(
	version flow.Version, exporter netip.Addr, es *ExporterStats, payload []byte, dst []flow.Record,
) ([]flow.Record, *decodeError) {
	switch version {
	case flow.VersionNetFlowV5:
		return decodeNetFlowV5(exporter, payload, dst)
	case flow.VersionNetFlowV8:
		return decodeNetFlowV8(exporter, payload, dst)
	case flow.VersionNetFlowV9:
		issue := func(reason string) { es.countError(flow.VersionNetFlowV9, reason) }
		return d.decodeNetFlowV9(exporter, payload, dst, issue)
	case flow.VersionIPFIX:
		issue := func(reason string) { es.countError(flow.VersionIPFIX, reason) }
		return d.decodeIPFIX(exporter, payload, dst, issue)
	case flow.VersionSFlowV5:
		issue := func(reason string) { es.countError(flow.VersionSFlowV5, reason) }
		return d.decodeSFlowV5(exporter, payload, dst, issue)
	case flow.VersionUnknown:
		return dst, &decodeError{reason: ReasonUnsupportedVersion, detail: "unknown version"}
	default:
		return dst, &decodeError{reason: ReasonUnsupportedVersion, detail: "unknown version"}
	}
}

// sniffVersion identifies the wire protocol from the first bytes.
//
// NetFlow and IPFIX carry a 16-bit version first, sFlow a 32-bit one. The two
// cannot collide: an sFlow v5 datagram begins 0x00000005, and no NetFlow
// version is 0, so a zero first half-word can only be sFlow.
func sniffVersion(payload []byte) (flow.Version, *decodeError) {
	if len(payload) < minVersionBytes {
		return flow.VersionUnknown, malformed("datagram of %d bytes is shorter than any header", len(payload))
	}

	switch short := binary.BigEndian.Uint16(payload); short {
	case wireNetFlowV5:
		return flow.VersionNetFlowV5, nil
	case wireNetFlowV8:
		return flow.VersionNetFlowV8, nil
	case wireNetFlowV9:
		return flow.VersionNetFlowV9, nil
	case wireIPFIX:
		return flow.VersionIPFIX, nil
	case 0:
		if binary.BigEndian.Uint32(payload) == wireSFlowV5 {
			return flow.VersionSFlowV5, nil
		}
		return flow.VersionUnknown, &decodeError{
			reason: ReasonUnsupportedVersion,
			detail: fmt.Sprintf("unknown 32-bit version %d", binary.BigEndian.Uint32(payload)),
		}
	default:
		return flow.VersionUnknown, &decodeError{
			reason: ReasonUnsupportedVersion,
			detail: fmt.Sprintf("unknown 16-bit version %d", short),
		}
	}
}
