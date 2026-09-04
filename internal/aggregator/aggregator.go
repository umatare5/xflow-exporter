// Package aggregator accumulates flow records into bounded in-memory tables
// the collectors read at scrape time.
package aggregator

import (
	"context"
	"net/netip"
	"strconv"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// Modules says which aggregations are enabled. A disabled aggregation costs
// neither memory nor work.
type Modules struct {
	Exporters    bool
	Hosts        bool
	Services     bool
	Destinations bool
	TCPFlags     bool
	DSCP         bool
	ASNs         bool
	Applications bool
	Countries    bool
	Threats      bool
}

// Any reports whether any aggregation is enabled.
func (m Modules) Any() bool {
	return m.Exporters || m.Hosts || m.Services || m.Destinations ||
		m.TCPFlags || m.DSCP ||
		m.ASNs || m.Applications || m.Countries || m.Threats
}

// Table keys. Label values are derived from these at scrape time.

// ExporterKey keys the per-device aggregation.
type ExporterKey struct {
	Exporter netip.Addr
	Version  flow.Version
}

// HostKey keys the address-pair aggregation. The interfaces the flow
// crossed key it too, so one pair reached over two paths reads as two
// entries rather than one sum a path cannot be read out of.
type HostKey struct {
	Exporter netip.Addr
	Src      netip.Addr
	Dst      netip.Addr
	InputIf  uint32
	OutputIf uint32
}

// ServiceKey keys the address-pair-with-service aggregation. Port is the
// destination port: the service side of the conversation as exported.
type ServiceKey struct {
	Exporter netip.Addr
	Src      netip.Addr
	Dst      netip.Addr
	Protocol uint8
	Port     uint16
	InputIf  uint32
	OutputIf uint32
}

// protocolTCP is the only protocol whose control bits a record can carry.
const protocolTCP = 6

// TCPFlagsKey keys the control-bit profile. The bits are the OR of what the
// flow's packets carried, so one entry reads as how a conversation behaved
// rather than as one packet: a scan is one entry of bare SYN against many
// destinations, where a working session ORs its way to SYN, ACK, PSH and FIN.
type TCPFlagsKey struct {
	Exporter netip.Addr
	Flags    uint8
}

// ecnBits is how far the TOS byte is shifted to leave the code point. The two
// it drops are ECN, which is congestion signaling rather than a class, and
// folding them in would split every class in four.
const ecnBits = 2

// DSCPKey keys the differentiated-services code point, the top six bits of
// the TOS byte.
type DSCPKey struct {
	Exporter netip.Addr
	DSCP     uint8
}

// DestinationKey keys the aggregation ServiceKey becomes without its source:
// what one service received, summed over every host that reached it. It is
// directional rather than a host total, so an ingress-only pair of
// observation points keys the two directions separately.
type DestinationKey struct {
	Exporter netip.Addr
	Dst      netip.Addr
	Protocol uint8
	Port     uint16
}

// ASNKey keys the AS-pair aggregation. A zero is the absence of an answer,
// which is what AS 0 is reserved to mean, and is left as the number: unlike a
// country, an AS has a spelling for "none" that an operator already reads.
type ASNKey struct {
	Exporter netip.Addr
	SrcAS    uint32
	DstAS    uint32
}

// CountryKey keys the country-pair aggregation. The codes are ISO two-letter
// spellings filled by enrichment, so the table needs a country database to
// hold anything.
type CountryKey struct {
	Exporter netip.Addr
	Src      string
	Dst      string
}

// ThreatKey keys the flagged-address aggregation. Only an address a
// reputation source flagged appears, so the table holds what is worth acting
// on rather than one entry per address seen.
type ThreatKey struct {
	Exporter  netip.Addr
	Address   netip.Addr
	Direction string
	InputIf   uint32
	OutputIf  uint32
}

// The sides a flagged address was seen on.
const (
	DirectionSrc = "src"
	DirectionDst = "dst"
)

// AppKey keys the application aggregation. Name is the resolved or inline
// application name, or the numbered identifier where no name is known.
type AppKey struct {
	Exporter netip.Addr
	Name     string
}

// Aggregator owns the tables and the eviction sweep.
type Aggregator struct {
	modules Modules
	cfg     config.Aggregation

	exporters *table[ExporterKey]
	hosts     *table[HostKey]
	services  *table[ServiceKey]
	// destinations is the aggregation services becomes without the source,
	// so it also admits a record whose source never resolved. It is enabled
	// and swept independently of services.
	destinations *table[DestinationKey]
	tcpFlags     *table[TCPFlagsKey]
	dscp         *table[DSCPKey]
	asns         *table[ASNKey]
	apps         *table[AppKey]
	countries    *table[CountryKey]
	threats      *table[ThreatKey]

	// now is pinned by tests.
	now func() time.Time
}

// New creates an aggregator with the enabled modules' tables.
func New(cfg config.Aggregation, modules Modules) *Aggregator {
	a := &Aggregator{
		modules: modules,
		cfg:     cfg,
		now:     time.Now,
	}
	if modules.Exporters {
		a.exporters = newTable[ExporterKey](cfg.MaxEntries)
	}
	if modules.Hosts {
		a.hosts = newTable[HostKey](cfg.MaxEntries)
	}
	if modules.Services {
		a.services = newTable[ServiceKey](cfg.MaxEntries)
	}
	if modules.Destinations {
		a.destinations = newTable[DestinationKey](cfg.MaxEntries)
	}
	if modules.TCPFlags {
		a.tcpFlags = newTable[TCPFlagsKey](cfg.MaxEntries)
	}
	if modules.DSCP {
		a.dscp = newTable[DSCPKey](cfg.MaxEntries)
	}
	if modules.ASNs {
		a.asns = newTable[ASNKey](cfg.MaxEntries)
	}
	if modules.Applications {
		a.apps = newTable[AppKey](cfg.MaxEntries)
	}
	if modules.Countries {
		a.countries = newTable[CountryKey](cfg.MaxEntries)
	}
	if modules.Threats {
		a.threats = newTable[ThreatKey](cfg.MaxEntries)
	}
	return a
}

// Ingest accumulates one batch of records into every enabled table, with the
// sampling correction applied to bytes and packets. Flow counts stay as
// exported: a packet-sampled protocol observes flows, it does not count them.
func (a *Aggregator) Ingest(records []flow.Record) {
	now := a.now().UnixNano()

	for i := range records {
		r := &records[i]

		rate := uint64(r.SamplingRate)
		if rate == 0 {
			rate = 1
		}
		bytes := r.Bytes * rate
		packets := r.Packets * rate

		a.ingestOne(r, bytes, packets, now)
	}
}

// ingestOne feeds the enabled tables that have a key for this record. A
// record lacking an aggregation's dimensions is absent from that
// aggregation rather than keyed by fabricated zeros.
func (a *Aggregator) ingestOne(r *flow.Record, bytes, packets uint64, now int64) {
	if a.exporters != nil {
		a.exporters.add(ExporterKey{Exporter: r.Exporter, Version: r.Version},
			bytes, packets, r.Flows, now)
	}

	if a.hosts != nil && r.SrcAddr.IsValid() && r.DstAddr.IsValid() {
		a.hosts.add(HostKey{
			Exporter: r.Exporter,
			Src:      r.SrcAddr,
			Dst:      r.DstAddr,
			InputIf:  r.InputIf,
			OutputIf: r.OutputIf,
		}, bytes, packets, r.Flows, now)
	}

	if a.services != nil && r.SrcAddr.IsValid() && r.DstAddr.IsValid() && r.Protocol != 0 {
		a.services.add(ServiceKey{
			Exporter: r.Exporter,
			Src:      r.SrcAddr,
			Dst:      r.DstAddr,
			Protocol: r.Protocol,
			Port:     r.DstPort,
			InputIf:  r.InputIf,
			OutputIf: r.OutputIf,
		}, bytes, packets, r.Flows, now)
	}

	// The source is not read here, so a record whose source never resolved
	// still names the service it reached.
	if a.destinations != nil && r.DstAddr.IsValid() && r.Protocol != 0 {
		a.destinations.add(DestinationKey{
			Exporter: r.Exporter,
			Dst:      r.DstAddr,
			Protocol: r.Protocol,
			Port:     r.DstPort,
		}, bytes, packets, r.Flows, now)
	}

	// Keyed on whether the device reported the bits, not on their value: a
	// segment setting none is a NULL scan rather than a field left unset,
	// and a breakdown of control bits is where that has to be visible.
	if a.tcpFlags != nil && r.Protocol == protocolTCP && r.TCPFlagsReported {
		a.tcpFlags.add(TCPFlagsKey{Exporter: r.Exporter, Flags: r.TCPFlags},
			bytes, packets, r.Flows, now)
	}

	// Keyed on whether the device reported the byte, not on its value: a
	// code point of zero is best-effort traffic and belongs in the table.
	if a.dscp != nil && r.TOSReported {
		a.dscp.add(DSCPKey{Exporter: r.Exporter, DSCP: r.TOS >> ecnBits},
			bytes, packets, r.Flows, now)
	}

	if a.asns != nil && (r.SrcAS != 0 || r.DstAS != 0) {
		a.asns.add(ASNKey{Exporter: r.Exporter, SrcAS: r.SrcAS, DstAS: r.DstAS},
			bytes, packets, r.Flows, now)
	}

	if a.apps != nil {
		if name := applicationName(r); name != "" {
			a.apps.add(AppKey{Exporter: r.Exporter, Name: name},
				bytes, packets, r.Flows, now)
		}
	}

	// A record neither side of which resolved to a country feeds nothing:
	// a pair of empty codes is absence rather than a place.
	if a.countries != nil && (r.SrcCountry != "" || r.DstCountry != "") {
		a.countries.add(CountryKey{Exporter: r.Exporter, Src: r.SrcCountry, Dst: r.DstCountry},
			bytes, packets, r.Flows, now)
	}

	a.ingestThreats(r, bytes, packets, now)
}

// ingestThreats records the flagged sides of one record. A record with
// neither side flagged feeds nothing, which is what keeps the table to the
// addresses worth acting on.
func (a *Aggregator) ingestThreats(r *flow.Record, bytes, packets uint64, now int64) {
	if a.threats == nil {
		return
	}

	if r.SrcFlagged {
		a.threats.add(ThreatKey{
			Exporter:  r.Exporter,
			Address:   r.SrcAddr,
			Direction: DirectionSrc,
			InputIf:   r.InputIf,
			OutputIf:  r.OutputIf,
		}, bytes, packets, r.Flows, now)
	}
	if r.DstFlagged {
		a.threats.add(ThreatKey{
			Exporter:  r.Exporter,
			Address:   r.DstAddr,
			Direction: DirectionDst,
			InputIf:   r.InputIf,
			OutputIf:  r.OutputIf,
		}, bytes, packets, r.Flows, now)
	}
}

// applicationName renders the application dimension: the resolved or inline
// name, the numbered identifier when only that is known, and nothing when
// the record carried no application at all.
func applicationName(r *flow.Record) string {
	if r.AppName != "" {
		return r.AppName
	}
	if r.AppID != 0 {
		return formatAppID(r.AppID)
	}
	return ""
}

// formatAppID renders an applicationId as engine:selector, the split RFC
// 6759 defines.
func formatAppID(appID uint32) string {
	const selectorBits = 24

	engine := appID >> selectorBits
	selector := appID & (1<<selectorBits - 1)
	return strconv.FormatUint(uint64(engine), 10) + ":" + strconv.FormatUint(uint64(selector), 10)
}

// Run sweeps idle entries until ctx ends. The interval is a quarter of the
// TTL so an idle entry outlives its TTL by at most that much.
func (a *Aggregator) Run(ctx context.Context) {
	const sweepDivisor = 4

	interval := a.cfg.EntryTTL / sweepDivisor
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sweep()
		}
	}
}

// sweep drops entries idle past the TTL in every enabled table.
func (a *Aggregator) sweep() {
	cutoff := a.now().Add(-a.cfg.EntryTTL).UnixNano()
	for _, t := range a.tables() {
		_, _ = t.sweep(cutoff)
	}
}

// sweepable lets the enabled tables be walked without their key types.
type sweepable interface {
	sweep(cutoff int64) (int, Totals)
	size() int
	stats() (idle, folds uint64)
}

// stats reports the eviction counters.
func (t *table[K]) stats() (idle, folds uint64) {
	return t.idleEvictions.Load(), t.capacityFolds.Load()
}

// tableCount is how many aggregations exist, sizing the walk below.
const tableCount = 10

// tables returns the enabled tables keyed by their aggregation label value.
func (a *Aggregator) tables() map[string]sweepable {
	tables := make(map[string]sweepable, tableCount)
	if a.exporters != nil {
		tables["exporters"] = a.exporters
	}
	if a.hosts != nil {
		tables["hosts"] = a.hosts
	}
	if a.services != nil {
		tables["services"] = a.services
	}
	if a.destinations != nil {
		tables["destinations"] = a.destinations
	}
	if a.tcpFlags != nil {
		tables["tcp_flags"] = a.tcpFlags
	}
	if a.dscp != nil {
		tables["dscp"] = a.dscp
	}
	if a.asns != nil {
		tables["asns"] = a.asns
	}
	if a.apps != nil {
		tables["applications"] = a.apps
	}
	if a.countries != nil {
		tables["countries"] = a.countries
	}
	if a.threats != nil {
		tables["threats"] = a.threats
	}
	return tables
}

// TableHealth is one table's self-monitoring reading.
type TableHealth struct {
	Aggregation   string
	Entries       int
	IdleEvictions uint64
	CapacityFolds uint64
}

// Health reports every enabled table's size and eviction counters.
func (a *Aggregator) Health() []TableHealth {
	tables := a.tables()
	health := make([]TableHealth, 0, len(tables))
	for name, t := range tables {
		idle, folds := t.stats()
		health = append(health, TableHealth{
			Aggregation:   name,
			Entries:       t.size(),
			IdleEvictions: idle,
			CapacityFolds: folds,
		})
	}
	return health
}

// Snapshot accessors for the collectors. Each returns nil entries when its
// module is disabled.

// Exporters reads the per-device table.
func (a *Aggregator) Exporters() ([]EntrySnapshot[ExporterKey], Totals) {
	if a.exporters == nil {
		return nil, Totals{}
	}
	return a.exporters.snapshot()
}

// Hosts reads the address-pair table.
func (a *Aggregator) Hosts() ([]EntrySnapshot[HostKey], Totals) {
	if a.hosts == nil {
		return nil, Totals{}
	}
	return a.hosts.snapshot()
}

// Services reads the service table.
func (a *Aggregator) Services() ([]EntrySnapshot[ServiceKey], Totals) {
	if a.services == nil {
		return nil, Totals{}
	}
	return a.services.snapshot()
}

// Destinations reads the destination-service table.
func (a *Aggregator) Destinations() ([]EntrySnapshot[DestinationKey], Totals) {
	if a.destinations == nil {
		return nil, Totals{}
	}
	return a.destinations.snapshot()
}

// TCPFlags reads the control-bit table.
func (a *Aggregator) TCPFlags() ([]EntrySnapshot[TCPFlagsKey], Totals) {
	if a.tcpFlags == nil {
		return nil, Totals{}
	}
	return a.tcpFlags.snapshot()
}

// DSCP reads the code-point table.
func (a *Aggregator) DSCP() ([]EntrySnapshot[DSCPKey], Totals) {
	if a.dscp == nil {
		return nil, Totals{}
	}
	return a.dscp.snapshot()
}

// ASNs reads the AS-pair table.
func (a *Aggregator) ASNs() ([]EntrySnapshot[ASNKey], Totals) {
	if a.asns == nil {
		return nil, Totals{}
	}
	return a.asns.snapshot()
}

// Applications reads the application table.
func (a *Aggregator) Applications() ([]EntrySnapshot[AppKey], Totals) {
	if a.apps == nil {
		return nil, Totals{}
	}
	return a.apps.snapshot()
}

// Countries reads the country-pair table.
func (a *Aggregator) Countries() ([]EntrySnapshot[CountryKey], Totals) {
	if a.countries == nil {
		return nil, Totals{}
	}
	return a.countries.snapshot()
}

// Threats reads the flagged-address table.
func (a *Aggregator) Threats() ([]EntrySnapshot[ThreatKey], Totals) {
	if a.threats == nil {
		return nil, Totals{}
	}
	return a.threats.snapshot()
}
