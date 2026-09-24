// Package flow holds the normalized flow record every decoder produces and
// every downstream stage consumes.
package flow

import (
	"math"
	"math/bits"
	"net/netip"
	"time"
)

// labelUnknown is the label value of an answer the wire did not give. It is
// what `src_country` already spells, so one vocabulary covers every absence.
const labelUnknown = "unknown"

// Version identifies the wire protocol a record arrived in. The values are the
// `version` label of the decode metrics, so they must not drift.
type Version uint8

// The supported wire protocols. VersionUnknown is what a datagram no decoder
// claims reports as.
const (
	VersionUnknown Version = iota
	VersionNetFlowV5
	VersionNetFlowV8
	VersionNetFlowV9
	VersionIPFIX
	VersionSFlowV5
)

// String returns the `version` label value.
func (v Version) String() string {
	switch v {
	case VersionNetFlowV5:
		return "netflow_v5"
	case VersionNetFlowV8:
		return "netflow_v8"
	case VersionNetFlowV9:
		return "netflow_v9"
	case VersionIPFIX:
		return "ipfix"
	case VersionSFlowV5:
		return "sflow_v5"
	case VersionUnknown:
		return labelUnknown
	default:
		return labelUnknown
	}
}

// Direction is the observation point a record was taken at, as IE 61 numbers
// it. RFC 7011 makes the point part of a flow's identity, so a device
// watching one path at both ends reports the same traffic twice and only the
// point tells the two readings apart.
type Direction uint8

// The observation points. DirectionUnknown is the zero value and carries the
// absence of an answer: a protocol with no such element, or a source no one
// interface owns.
const (
	DirectionUnknown Direction = iota
	DirectionIngress
	DirectionEgress
)

// String returns the `direction` label value.
func (d Direction) String() string {
	switch d {
	case DirectionIngress:
		return "ingress"
	case DirectionEgress:
		return "egress"
	case DirectionUnknown:
		return labelUnknown
	default:
		return labelUnknown
	}
}

// AppSelectorBits is the width of the selector in Record.AppID, below its
// 8-bit classification engine.
const AppSelectorBits = 24

// Record is one flow reading normalized from any supported protocol. A field
// the protocol or the record did not carry stays at its zero value, and the
// *Reported flags and Duration's second result distinguish that absence from
// a zero the device measured.
type Record struct {
	// Exporter is the device the datagram came from, unmapped.
	Exporter netip.Addr
	// Version is the wire protocol that carried the record.
	Version Version
	// ODID is the observation domain the record arrived in: the Source ID on
	// v9, the Observation Domain ID on IPFIX, the sub-agent id on sFlow and
	// the aggregation method on v8, each keeping its own templates and
	// sequence space. A v5 export carries no domain field and reports zero,
	// which is also what an sFlow agent numbering one sub-agent reports.
	ODID uint32

	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	// Protocol is the IP protocol number.
	Protocol uint8
	// Direction is the observation point the device took the reading at,
	// which separates the two readings a path watched at both ends gives.
	Direction Direction
	TOS       uint8
	// TOSReported records that a device carried the TOS byte, which its value
	// cannot: a DSCP of zero is best-effort traffic, not a field left unset,
	// and the two would otherwise be one series.
	TOSReported bool
	TCPFlags    uint8
	// TCPFlagsReported records that a device carried the control bits, which
	// their value cannot: a TCP segment may legitimately set none, a NULL
	// scan being defined by setting none, and that is exactly the traffic a
	// control-bit breakdown exists to surface.
	TCPFlagsReported bool

	InputIf  uint32
	OutputIf uint32

	// Bytes and Packets are as exported: sampling correction is applied
	// downstream, where the rate in force is known.
	Bytes   uint64
	Packets uint64
	// BytesReported and PacketsReported record that the record carried each
	// count, which the counts cannot: a template keeping its counters in
	// elements this decoder skips leaves them at zero, and that zero is not
	// an empty flow.
	BytesReported   bool
	PacketsReported bool
	// Flows is how many flows this record aggregates: 1 for a per-flow
	// protocol, the device's own count for a NetFlow v8 aggregate that
	// carries one -- the Catalyst methods 6-8 do not, and read as 1.
	Flows uint64
	// FlowsReported records that the count came from the wire, which the
	// count cannot: a v9 or IPFIX template carrying IE 3 describes a cache
	// the device folded, and zero is a reading that cache can legitimately
	// give for an interval it contributed nothing to.
	FlowsReported bool

	SrcAS uint32
	DstAS uint32

	// SrcMask and DstMask are prefix lengths. On a v8 prefix aggregate the
	// address fields carry the prefix base rather than a host.
	SrcMask uint8
	DstMask uint8

	// Start and End are absolute flow times, zero where the record carried
	// none. A v5, v8 or v9 record dates them relative to the device's uptime,
	// and the decoder anchors them to the export timestamp.
	Start time.Time
	End   time.Time

	// SamplingRate is the rate in force for the record: carried by the export
	// itself on v5 and sFlow, stamped from the observation domain's options
	// declaration on v9 and IPFIX. Zero means neither declared one, not an
	// unsampled export.
	SamplingRate uint32

	// AppID is the applicationId (IE 95): the RFC 6759 classification engine
	// over a selector AppSelectorBits wide, whatever width the device
	// exported, which is the split published downstream. Zero means the
	// record carried none.
	AppID uint32
	// AppName and AppCategory are resolved from the device's own application
	// table options, or carried inline where the vendor exports strings.
	AppName     string
	AppCategory string

	// SrcFlagged and DstFlagged mark an address a reputation source reported
	// as abusive. They are false until such a source is enabled and holds a
	// verdict, which is absence rather than a clean bill of health.
	SrcFlagged bool
	DstFlagged bool

	// SrcVLAN and DstVLAN are the VLANs a mapping file puts each address on,
	// which is a property of the address rather than of the path the frame
	// took: a device that reports a VLAN of its own reports the tag on the
	// frame it saw or the VLAN of the interface it observed. Zero is the null
	// VLAN ID of 802.1Q, so it cannot collide with a VLAN an operator
	// numbered.
	SrcVLAN uint16
	DstVLAN uint16

	// SrcCountry and DstCountry are ISO codes filled by enrichment. No flow
	// protocol exports them, so they are empty unless a country database is
	// enabled and knew the address.
	SrcCountry string
	DstCountry string
}

// Aggregated reports a record the device folded from several flows before
// exporting it. A NetFlow v8 cache re-reports what the main cache already
// counted under one method's dimensions, so a device running ten of them
// hands the same bytes over ten times. A v9 or IPFIX cache does the same
// wherever its template carries IE 3, which RFC 7015 gives an aggregate to
// declare its fold with. The element's presence classifies the record; its
// value does not, a fold reporting no flows for an interval being a reading
// rather than a per-flow record.
func (r *Record) Aggregated() bool {
	return r.Version == VersionNetFlowV8 || r.FlowsReported
}

// Duration returns the flow duration, and false when the record did not carry
// both instants. A zero duration is a legal reading for a single-packet flow.
func (r *Record) Duration() (time.Duration, bool) {
	if r.Start.IsZero() || r.End.IsZero() {
		return 0, false
	}
	return r.End.Sub(r.Start), true
}

// Corrected returns the counts times the rate in force, a record carrying no
// rate multiplying by one. Both products saturate rather than wrap, because a
// counter handed a reading below the one before it reads as a reset.
func (r *Record) Corrected() (bytes, packets uint64) {
	rate := uint64(r.SamplingRate)
	if rate == 0 {
		rate = 1
	}
	return saturatingProduct(r.Bytes, rate), saturatingProduct(r.Packets, rate)
}

func saturatingProduct(count, rate uint64) uint64 {
	hi, lo := bits.Mul64(count, rate)
	if hi != 0 {
		return math.MaxUint64
	}
	return lo
}
