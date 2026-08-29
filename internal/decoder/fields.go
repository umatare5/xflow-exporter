// Package decoder turns received datagrams into normalized flow records.
// This file maps information elements into flow.Record. NetFlow v9 field
// types and IPFIX IANA information elements share one numbering, which is
// what lets both protocols share this layer.
package decoder

import (
	"encoding/binary"
	"math"
	"net/netip"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// Sampled packet section elements. NetFlow-Lite devices export one sampled
// packet per record: v9 mode ships the layer-2 section in the deprecated
// field 104, measured on Cisco devices, and IPFIX mode in IE 315, with the
// original frame length in IE 312 and an IP-only section in IE 313.
const (
	fieldPacketSectionV9Data   = 104
	fieldDataLinkFrameSize     = 312
	fieldIPHeaderPacketSection = 313
	fieldDataLinkFrameSection  = 315
)

// The code point IE 195 carries occupies the TOS byte less its two ECN bits,
// and spans six bits: a wider value is not a code point.
const (
	ecnBits = 2
	maxDSCP = 0x3F
)

// Vendor information elements mapped beyond the IANA set.
const (
	// Cisco AVC exports the application identifier as IANA IE 95; the name
	// and category arrive through the application-table options this file's
	// options reader captures.
	fieldApplicationID = 95

	// PAN-OS exports its application name inside NetFlow v9 records using a
	// private type number, there being no enterprise bit in v9. The User-ID
	// beside it is not read: a user identity is high-cardinality and
	// personally identifying, so no series would be allowed to carry it.
	fieldPanAppID = 56701
)

// ciscoPEN is the Cisco private enterprise number, under which the AVC
// application attributes are exported.
const ciscoPEN = 9

// Cisco AVC application attribute elements under ciscoPEN.
const (
	fieldCiscoAppCategory = 12232
)

// fieldState accumulates per-record values that need resolution after every
// field is read: the flow clocks and the egress fallback counters. It also
// carries the interner vendor strings resolve through.
type fieldState struct {
	firstUptimeMs, lastUptimeMs uint32
	hasUptime                   bool
	startAbs, endAbs            time.Time
	outBytes, outPackets        uint64
	intern                      *interner

	// The two address families, kept apart until every field is read: which
	// pair the device measured and which it zero-filled is a property of
	// the pairs together, not of any one element.
	v4, v6 addrPair

	// A sampled packet section, kept for resolution after every field is
	// read so the device's own parsed fields can take precedence.
	frameSection []byte
	ipSection    []byte
	frameSize    uint64
}

// addrPair holds one address family's two elements as they were read.
type addrPair struct {
	src, dst netip.Addr
}

// finishRecord resolves the accumulated state into the record and stamps the
// domain sampling rate where the record carried none.
func finishRecord(r *flow.Record, state *fieldState, bootTime time.Time, domain *domainState) {
	resolveAddrs(r, state)
	resolvePacketSection(r, state)

	// An egress-only template carries OUT_* alone; both present would double
	// the flow if summed, so IN_* wins.
	if r.Bytes == 0 {
		r.Bytes = state.outBytes
	}
	if r.Packets == 0 {
		r.Packets = state.outPackets
	}

	switch {
	case !state.startAbs.IsZero() || !state.endAbs.IsZero():
		r.Start = state.startAbs
		r.End = state.endAbs
	case state.hasUptime && !bootTime.IsZero():
		r.Start = bootTime.Add(time.Duration(state.firstUptimeMs) * time.Millisecond)
		r.End = bootTime.Add(time.Duration(state.lastUptimeMs) * time.Millisecond)
	}

	if r.SamplingRate == 0 {
		r.SamplingRate = domain.samplingRate.Load()
	}
}

// resolveAddrs settles which address family the device actually measured.
//
// A template announcing both families carries four address elements per
// record and zero-fills the pair it is not using. The zero value of either
// family is a valid address rather than an absent one, so no element can be
// judged alone: a flow really from 0.0.0.0 and an unused IPv4 pair are the
// same four bytes, and only the other family's pair tells them apart. The
// pair holding a reading is therefore taken whole -- taking each side on its
// own merit produced a record whose source and destination were of different
// families, which no flow is.
//
// Where neither pair holds one, whichever family the template carried still
// stands: an all-zero single-family record keeps the reading the device sent
// rather than falling to absence. A template mixing one family's source with
// the other's destination keeps both, the losing pair filling only the side
// the winner left absent -- nothing writes the record's addresses before
// this runs, so the winning pair can be taken whole.
//
// Where both pairs hold a reading the record contradicts itself, and IPv4 is
// taken. There is no right answer to pick, only a settled one: an unsettled
// tie would key one flow into two series.
func resolveAddrs(r *flow.Record, state *fieldState) {
	first, second := state.v4, state.v6
	if !first.carries() && second.carries() {
		first, second = second, first
	}

	r.SrcAddr, r.DstAddr = first.src, first.dst
	if !r.SrcAddr.IsValid() {
		r.SrcAddr = second.src
	}
	if !r.DstAddr.IsValid() {
		r.DstAddr = second.dst
	}
}

// carries reports whether a pair holds a reading rather than the filler a
// dual-family template writes into the family it is not using. The zero
// netip.Addr is not the unspecified address, so an absent element has to be
// excluded by validity first.
func (p addrPair) carries() bool {
	return (p.src.IsValid() && !p.src.IsUnspecified()) ||
		(p.dst.IsValid() && !p.dst.IsUnspecified())
}

// resolvePacketSection decodes a sampled packet section through the header
// walkers the sFlow decoder uses — NetFlow-Lite is packet sampling in a
// NetFlow envelope, so the two share one parse.
//
// Fields the device parsed itself win: the section fills only what is still
// absent, and a record carrying both addresses and a section keeps the
// device's own classification.
func resolvePacketSection(r *flow.Record, state *fieldState) {
	if len(state.frameSection) == 0 && len(state.ipSection) == 0 {
		return
	}

	if !r.SrcAddr.IsValid() && !r.DstAddr.IsValid() {
		switch {
		case len(state.frameSection) > 0:
			readEthernetFrame(state.frameSection, r)
		case len(state.ipSection) > 0:
			readIPPacket(state.ipSection, r)
		}
	}

	// One record describes one sampled packet, which is the protocol's own
	// semantics rather than a fabricated reading. The frame length is the
	// original frame's, a-la the sFlow frameLength.
	if r.Packets == 0 {
		r.Packets = 1
	}
	if r.Bytes == 0 {
		r.Bytes = state.frameSize
	}
}

// applyField maps one field into the record. An unknown element is skipped by
// length, which is what lets a template carry fields this exporter does not
// model without desynchronizing the ones it does.
func applyField(r *flow.Record, state *fieldState, fieldType uint16, enterprise uint32, value []byte) {
	if enterprise != 0 {
		// No enterprise element is mapped inside data records yet; the AVC
		// attributes arrive through options records instead.
		return
	}

	switch fieldType {
	case fieldInBytes:
		r.Bytes, _ = beUint(value)
	case fieldInPackets:
		r.Packets, _ = beUint(value)
	case fieldOutBytes:
		state.outBytes, _ = beUint(value)
	case fieldOutPackets:
		state.outPackets, _ = beUint(value)
	case fieldProtocol:
		if v, ok := beUint8(value); ok {
			r.Protocol = v
		}
	case fieldSrcTOS:
		if v, ok := beUint8(value); ok {
			r.TOS = v
			r.TOSReported = true
		}
	case fieldDSCP:
		// The element holds the code point right-aligned where the record
		// holds the whole TOS byte. IE 5 outranks it in a template carrying
		// both, that element being the byte itself including the ECN bits.
		if v, ok := beUint8(value); ok && v <= maxDSCP && !r.TOSReported {
			r.TOS = v << ecnBits
			r.TOSReported = true
		}
	case fieldTCPFlags:
		// The element is unsigned16 and the octet form is reduced-size
		// encoding of it, so an exporter that declines to reduce is
		// conformant. RFC 9565 puts the control bits in the low octet and
		// tells a collector to ignore what sits above them, which is a mask:
		// refusing the value would drop the eight bits reported alongside.
		if v, ok := beUint16(value); ok {
			r.TCPFlags = uint8(v & math.MaxUint8)
			r.TCPFlagsReported = true
		}
	case fieldL4SrcPort:
		if v, ok := beUint16(value); ok {
			r.SrcPort = v
		}
	case fieldL4DstPort:
		if v, ok := beUint16(value); ok {
			r.DstPort = v
		}
	case fieldIPv4SrcAddr:
		if len(value) == ipv4Len {
			state.v4.src = netip.AddrFrom4([4]byte(value))
		}
	case fieldIPv4DstAddr:
		if len(value) == ipv4Len {
			state.v4.dst = netip.AddrFrom4([4]byte(value))
		}
	case fieldIPv6SrcAddr:
		if len(value) == ipv6Len {
			state.v6.src = addrFrom16([16]byte(value))
		}
	case fieldIPv6DstAddr:
		if len(value) == ipv6Len {
			state.v6.dst = addrFrom16([16]byte(value))
		}
	case fieldSrcMask, fieldIPv6SrcMask:
		if v, ok := beUint8(value); ok {
			r.SrcMask = v
		}
	case fieldDstMask, fieldIPv6DstMask:
		if v, ok := beUint8(value); ok {
			r.DstMask = v
		}
	case fieldInputSNMP:
		if v, ok := beUint32(value); ok {
			r.InputIf = v
		}
	case fieldOutputSNMP:
		if v, ok := beUint32(value); ok {
			r.OutputIf = v
		}
	case fieldSrcAS:
		if v, ok := beUint32(value); ok {
			r.SrcAS = v
		}
	case fieldDstAS:
		if v, ok := beUint32(value); ok {
			r.DstAS = v
		}
	case fieldApplicationID:
		if v, ok := beUint32(value); ok {
			r.AppID = v
		}
	default:
		applyRareField(r, state, fieldType, value)
	}
}

// applySectionField captures the sampled packet section elements.
func applySectionField(state *fieldState, fieldType uint16, value []byte) bool {
	switch fieldType {
	case fieldPacketSectionV9Data, fieldDataLinkFrameSection:
		state.frameSection = value
	case fieldIPHeaderPacketSection:
		state.ipSection = value
	case fieldDataLinkFrameSize:
		state.frameSize, _ = beUint(value)
	default:
		return false
	}
	return true
}

// applyRareField maps the elements off the hot path: the flow clocks, the
// packet sections and the vendor strings.
func applyRareField(r *flow.Record, state *fieldState, fieldType uint16, value []byte) {
	if applySectionField(state, fieldType, value) {
		return
	}

	switch fieldType {
	case fieldFirstSwitched:
		state.firstUptimeMs, _ = beUint32(value)
		state.hasUptime = true
	case fieldLastSwitched:
		state.lastUptimeMs, _ = beUint32(value)
		state.hasUptime = true
	case fieldFlowStartSeconds:
		if at, ok := unixSeconds(value); ok {
			state.startAbs = at
		}
	case fieldFlowEndSeconds:
		if at, ok := unixSeconds(value); ok {
			state.endAbs = at
		}
	case fieldFlowStartMilliseconds:
		if at, ok := unixMilliseconds(value); ok {
			state.startAbs = at
		}
	case fieldFlowEndMilliseconds:
		if at, ok := unixMilliseconds(value); ok {
			state.endAbs = at
		}
	case fieldApplicationName:
		// Some AVC configurations export the name inline instead of, or
		// alongside, the application table.
		r.AppName = state.intern.intern(value)
	case fieldPanAppID:
		r.AppName = state.intern.intern(value)
	}
}

// addrFrom16 reads a 16-byte address, returning the IPv4 form of one written
// as IPv4-mapped. A device that normalises its addresses into an IPv6 field
// sends ::ffff:198.51.100.7 for what its own IPv4 fields, every published
// list and every rendered label spell 198.51.100.7, and netip holds the two
// as distinct values: the threat set would miss the address it holds, and the
// aggregation would key one host twice under two spellings.
func addrFrom16(value [16]byte) netip.Addr {
	return netip.AddrFrom16(value).Unmap()
}

// beUint reads a big-endian unsigned integer of 1, 2, 4 or 8 bytes. Any other
// width reports false: the value cannot be represented, and guessing would
// publish a number the device did not send.
func beUint(value []byte) (uint64, bool) {
	switch len(value) {
	case 1:
		return uint64(value[0]), true
	case 2:
		return uint64(binary.BigEndian.Uint16(value)), true
	case 4:
		return uint64(binary.BigEndian.Uint32(value)), true
	case 8:
		return binary.BigEndian.Uint64(value), true
	default:
		return 0, false
	}
}

// The narrowing readers below report false for a value their target cannot
// hold: a four-byte protocol claiming 300 is garbage, and publishing a
// truncation of it would be a number the device did not send.

func beUint8(value []byte) (uint8, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxUint8 {
		return 0, false
	}
	return uint8(v), true
}

func beUint16(value []byte) (uint16, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxUint16 {
		return 0, false
	}
	return uint16(v), true
}

func beUint32(value []byte) (uint32, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxUint32 {
		return 0, false
	}
	return uint32(v), true
}

// unixSeconds and unixMilliseconds read an absolute flow clock. An epoch past
// the signed range is garbage rather than an instant.

func unixSeconds(value []byte) (time.Time, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0), true
}

func unixMilliseconds(value []byte) (time.Time, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(v)), true
}
