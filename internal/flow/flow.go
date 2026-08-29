// Package flow holds the normalized flow record every decoder produces and
// every downstream stage consumes.
package flow

import (
	"net/netip"
	"time"
)

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
		return "unknown"
	default:
		return "unknown"
	}
}

// Record is one flow reading normalized from any supported protocol. A field
// the protocol or the record did not carry stays at its zero value, and the
// Has* methods below distinguish the zeros where zero is also a legal reading.
type Record struct {
	// Exporter is the device the datagram came from, unmapped.
	Exporter netip.Addr
	// Version is the wire protocol that carried the record.
	Version Version

	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	// Protocol is the IP protocol number.
	Protocol uint8
	TOS      uint8
	TCPFlags uint8

	InputIf  uint32
	OutputIf uint32

	// Bytes and Packets are as exported: sampling correction is applied
	// downstream, where the rate in force is known.
	Bytes   uint64
	Packets uint64
	// Flows is how many flows this record aggregates: 1 for a per-flow
	// protocol, the device's own count for a NetFlow v8 aggregate.
	Flows uint64

	SrcAS uint32
	DstAS uint32

	// SrcMask and DstMask are prefix lengths. On a v8 prefix aggregate the
	// address fields carry the prefix base rather than a host.
	SrcMask uint8
	DstMask uint8

	// Start and End are absolute flow times, zero where the record carried
	// none. A v5/v9 record dates them relative to the device's uptime, and the
	// decoder anchors them to the export timestamp.
	Start time.Time
	End   time.Time

	// SamplingRate is the rate the record itself carried (v5 header, sFlow
	// sample). Zero means the record carried none, not an unsampled export.
	SamplingRate uint32
}

// Duration returns the flow duration, and false when the record did not carry
// both instants. A zero duration is a legal reading for a single-packet flow.
func (r *Record) Duration() (time.Duration, bool) {
	if r.Start.IsZero() || r.End.IsZero() {
		return 0, false
	}
	return r.End.Sub(r.Start), true
}
