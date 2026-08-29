// This file parses NetFlow v8, the router-aggregated legacy format J-Flow v8
// shares. Field layouts follow the flow-tools reference implementation.

package decoder

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	// netflowV8HeaderLen is fixed by the format: the v5 header with its
	// sampling halfword replaced by the aggregation method and that method's
	// export version, plus four reserved bytes.
	netflowV8HeaderLen = 28
	// netflowV8AggVersion is the only aggregation export version ever
	// shipped; flow-tools rejects everything else and so does this parser.
	netflowV8AggVersion = 2
	// netflowV8MaxCount bounds the claimed record count ahead of the length
	// check. The smallest record is 28 bytes, so no datagram can carry more.
	netflowV8MaxCount = 65535 / 28
)

// netflowV8Scheme describes one aggregation method: its fixed record length
// and the field reader that fills the dimensions the method carries. A
// dimension the method does not carry stays at its zero value.
type netflowV8Scheme struct {
	recordLen int
	read      func(record []byte, dst *flow.Record)
}

// netflowV8Schemes indexes the aggregation methods by the header's
// aggregation byte. Offsets mirror the flow-tools ftrec_v8_* structs.
var netflowV8Schemes = map[uint8]netflowV8Scheme{
	1:  {recordLen: 28, read: readV8AS},
	2:  {recordLen: 28, read: readV8ProtoPort},
	3:  {recordLen: 32, read: readV8SrcPrefix},
	4:  {recordLen: 32, read: readV8DstPrefix},
	5:  {recordLen: 40, read: readV8Prefix},
	6:  {recordLen: 32, read: readV8DestOnly},
	7:  {recordLen: 40, read: readV8SrcDst},
	8:  {recordLen: 44, read: readV8FullFlow},
	9:  {recordLen: 32, read: readV8TosAS},
	10: {recordLen: 32, read: readV8TosProtoPort},
	11: {recordLen: 32, read: readV8TosSrcPrefix},
	12: {recordLen: 32, read: readV8TosDstPrefix},
	13: {recordLen: 40, read: readV8TosPrefix},
	14: {recordLen: 40, read: readV8PrefixPort},
}

// decodeNetFlowV8 parses one v8 datagram and appends its records to dst.
// Trailing bytes past the claimed records are tolerated as padding, like v5.
func decodeNetFlowV8(exporter netip.Addr, payload []byte, dst []flow.Record) ([]flow.Record, *decodeError) {
	if len(payload) < netflowV8HeaderLen {
		return dst, malformed("v8 header needs %d bytes, datagram has %d", netflowV8HeaderLen, len(payload))
	}

	aggregation := payload[22]
	if aggVersion := payload[23]; aggVersion != netflowV8AggVersion {
		return dst, malformed("v8 aggregation export version %d, want %d", aggVersion, netflowV8AggVersion)
	}

	scheme, ok := netflowV8Schemes[aggregation]
	if !ok {
		return dst, &decodeError{
			reason: ReasonUnsupportedAggregation,
			detail: fmt.Sprintf("v8 aggregation method %d is not one this exporter knows", aggregation),
		}
	}

	count := int(binary.BigEndian.Uint16(payload[2:4]))
	if count < 1 || count > netflowV8MaxCount {
		return dst, malformed("v8 record count %d is outside 1-%d", count, netflowV8MaxCount)
	}
	if need := netflowV8HeaderLen + count*scheme.recordLen; len(payload) < need {
		return dst, malformed("v8 datagram of %d bytes cannot hold %d records of method %d needing %d",
			len(payload), count, aggregation, need)
	}

	sysUptimeMs := binary.BigEndian.Uint32(payload[4:8])
	exportSecs := binary.BigEndian.Uint32(payload[8:12])
	exportNanos := binary.BigEndian.Uint32(payload[12:16])
	bootTime := time.Unix(int64(exportSecs), int64(exportNanos)).
		Add(-time.Duration(sysUptimeMs) * time.Millisecond)

	for i := range count {
		record := payload[netflowV8HeaderLen+i*scheme.recordLen:]

		// The record is appended first and filled in place: filling a local
		// and appending it would escape one allocation per record through the
		// indirect scheme.read call.
		dst = append(dst, flow.Record{Exporter: exporter, Version: flow.VersionNetFlowV8})
		normalized := &dst[len(dst)-1]
		scheme.read(record, normalized)
		anchorV8Times(record, normalized, bootTime, aggregation)
	}

	return dst, nil
}

// anchorV8Times converts the record's uptime-relative instants. What precedes
// them is 12 bytes on every method but the Catalyst pair 7 and 8, which carry
// a second address and, on 8, both ports before the counters -- so only those
// two move First and Last off the flow-tools common offsets 12 and 16.
func anchorV8Times(record []byte, dst *flow.Record, bootTime time.Time, aggregation uint8) {
	firstAt, lastAt := 12, 16
	switch aggregation {
	case 6:
		firstAt, lastAt = 12, 16
	case 7:
		firstAt, lastAt = 16, 20
	case 8:
		firstAt, lastAt = 20, 24
	}

	first := binary.BigEndian.Uint32(record[firstAt : firstAt+4])
	last := binary.BigEndian.Uint32(record[lastAt : lastAt+4])
	dst.Start = bootTime.Add(time.Duration(first) * time.Millisecond)
	dst.End = bootTime.Add(time.Duration(last) * time.Millisecond)
}

// readV8Common reads the dFlows/dPkts/dOctets prefix methods 1-5 and 9-14
// share.
func readV8Common(record []byte, dst *flow.Record) {
	dst.Flows = uint64(binary.BigEndian.Uint32(record[0:4]))
	dst.Packets = uint64(binary.BigEndian.Uint32(record[4:8]))
	dst.Bytes = uint64(binary.BigEndian.Uint32(record[8:12]))
}

func readV8AS(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.SrcAS = uint32(binary.BigEndian.Uint16(record[20:22]))
	dst.DstAS = uint32(binary.BigEndian.Uint16(record[22:24]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[24:26]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[26:28]))
}

func readV8ProtoPort(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.Protocol = record[20]
	dst.SrcPort = binary.BigEndian.Uint16(record[24:26])
	dst.DstPort = binary.BigEndian.Uint16(record[26:28])
}

func readV8SrcPrefix(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.SrcMask = record[24]
	dst.SrcAS = uint32(binary.BigEndian.Uint16(record[26:28]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[28:30]))
}

func readV8DstPrefix(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.DstAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.DstMask = record[24]
	dst.DstAS = uint32(binary.BigEndian.Uint16(record[26:28]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[28:30]))
}

func readV8Prefix(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.DstAddr = netip.AddrFrom4([4]byte(record[24:28]))
	dst.DstMask = record[28]
	dst.SrcMask = record[29]
	dst.SrcAS = uint32(binary.BigEndian.Uint16(record[32:34]))
	dst.DstAS = uint32(binary.BigEndian.Uint16(record[34:36]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[36:38]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[38:40]))
}

// readV8DestOnly reads Catalyst method 6. It has no flow count of its own, so
// one record reads as one flow.
func readV8DestOnly(record []byte, dst *flow.Record) {
	dst.DstAddr = netip.AddrFrom4([4]byte(record[0:4]))
	dst.Packets = uint64(binary.BigEndian.Uint32(record[4:8]))
	dst.Bytes = uint64(binary.BigEndian.Uint32(record[8:12]))
	dst.Flows = 1
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[20:22]))
	dst.TOS = record[22]
	dst.TOSReported = true
}

func readV8SrcDst(record []byte, dst *flow.Record) {
	dst.DstAddr = netip.AddrFrom4([4]byte(record[0:4]))
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[4:8]))
	dst.Packets = uint64(binary.BigEndian.Uint32(record[8:12]))
	dst.Bytes = uint64(binary.BigEndian.Uint32(record[12:16]))
	dst.Flows = 1
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[24:26]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[26:28]))
	dst.TOS = record[28]
	dst.TOSReported = true
}

func readV8FullFlow(record []byte, dst *flow.Record) {
	dst.DstAddr = netip.AddrFrom4([4]byte(record[0:4]))
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[4:8]))
	dst.DstPort = binary.BigEndian.Uint16(record[8:10])
	dst.SrcPort = binary.BigEndian.Uint16(record[10:12])
	dst.Packets = uint64(binary.BigEndian.Uint32(record[12:16]))
	dst.Bytes = uint64(binary.BigEndian.Uint32(record[16:20]))
	dst.Flows = 1
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[28:30]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[30:32]))
	dst.TOS = record[32]
	dst.TOSReported = true
	dst.Protocol = record[33]
}

func readV8TosAS(record []byte, dst *flow.Record) {
	readV8AS(record, dst)
	dst.TOS = record[28]
	dst.TOSReported = true
}

func readV8TosProtoPort(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.Protocol = record[20]
	dst.TOS = record[21]
	dst.TOSReported = true
	dst.SrcPort = binary.BigEndian.Uint16(record[24:26])
	dst.DstPort = binary.BigEndian.Uint16(record[26:28])
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[28:30]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[30:32]))
}

func readV8TosSrcPrefix(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.SrcMask = record[24]
	dst.TOS = record[25]
	dst.TOSReported = true
	dst.SrcAS = uint32(binary.BigEndian.Uint16(record[26:28]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[28:30]))
}

func readV8TosDstPrefix(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.DstAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.DstMask = record[24]
	dst.TOS = record[25]
	dst.TOSReported = true
	dst.DstAS = uint32(binary.BigEndian.Uint16(record[26:28]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[28:30]))
}

func readV8TosPrefix(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.DstAddr = netip.AddrFrom4([4]byte(record[24:28]))
	dst.DstMask = record[28]
	dst.SrcMask = record[29]
	dst.TOS = record[30]
	dst.TOSReported = true
	dst.SrcAS = uint32(binary.BigEndian.Uint16(record[32:34]))
	dst.DstAS = uint32(binary.BigEndian.Uint16(record[34:36]))
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[36:38]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[38:40]))
}

func readV8PrefixPort(record []byte, dst *flow.Record) {
	readV8Common(record, dst)
	dst.SrcAddr = netip.AddrFrom4([4]byte(record[20:24]))
	dst.DstAddr = netip.AddrFrom4([4]byte(record[24:28]))
	dst.DstMask = record[28]
	dst.SrcMask = record[29]
	dst.TOS = record[30]
	dst.TOSReported = true
	dst.Protocol = record[31]
	dst.SrcPort = binary.BigEndian.Uint16(record[32:34])
	dst.DstPort = binary.BigEndian.Uint16(record[34:36])
	dst.InputIf = uint32(binary.BigEndian.Uint16(record[36:38]))
	dst.OutputIf = uint32(binary.BigEndian.Uint16(record[38:40]))
}
