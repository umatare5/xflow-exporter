// This file parses NetFlow v5, the fixed-format original that J-Flow v5
// shares byte for byte.

package decoder

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	// netflowV5HeaderLen and netflowV5RecordLen are fixed by the format.
	netflowV5HeaderLen = 24
	netflowV5RecordLen = 48
	// netflowV5MaxCount is the most records one v5 datagram may claim, fixed
	// by the format so an MTU-sized packet can carry them.
	netflowV5MaxCount = 30
	// netflowV5SamplingMask keeps the 14-bit interval of the sampling field,
	// whose top two bits carry the sampling mode.
	netflowV5SamplingMask = 0x3FFF
)

// decodeNetFlowV5 parses one v5 datagram and appends its records to dst.
//
// Trailing bytes past the claimed records are tolerated silently: some
// exporters pad the datagram, and the record count is the authoritative
// length. A count the payload cannot hold is malformed, not padding.
func (d *Decoder) decodeNetFlowV5(
	exporter netip.Addr, port uint16, payload []byte, dst []flow.Record,
) ([]flow.Record, *decodeError) {
	if len(payload) < netflowV5HeaderLen {
		return dst, malformed("v5 header needs %d bytes, datagram has %d", netflowV5HeaderLen, len(payload))
	}

	count := int(binary.BigEndian.Uint16(payload[2:4]))
	if count < 1 || count > netflowV5MaxCount {
		return dst, malformed("v5 record count %d is outside 1-%d", count, netflowV5MaxCount)
	}
	if need := netflowV5HeaderLen + count*netflowV5RecordLen; len(payload) < need {
		return dst, malformed("v5 datagram of %d bytes cannot hold %d records needing %d",
			len(payload), count, need)
	}

	// A v5 export carries no domain field, so the device is its own domain.
	// The records parse without one, so a device at its domain budget loses
	// the sequence and the clock accounting rather than the traffic the
	// datagram carries.
	domain := d.templates.domain(domainKey{exporter: exporter, proto: flow.VersionNetFlowV5})
	if domain != nil {
		domain.trackRecordSequence(port, binary.BigEndian.Uint32(payload[16:20]), uint32(count),
			binary.BigEndian.Uint16(payload[20:22]), true)
	}

	sysUptimeMs := binary.BigEndian.Uint32(payload[4:8])
	exportSecs := binary.BigEndian.Uint32(payload[8:12])
	exportNanos := binary.BigEndian.Uint32(payload[12:16])
	samplingRate := uint32(binary.BigEndian.Uint16(payload[22:24]) & netflowV5SamplingMask)

	clock := exportClock{
		at:       time.Unix(int64(exportSecs), int64(exportNanos)),
		uptimeMs: sysUptimeMs, hasUptime: true,
	}

	for i := range count {
		record := payload[netflowV5HeaderLen+i*netflowV5RecordLen:]
		dst = append(dst, netflowV5Record(exporter, record, clock, samplingRate, domain))
	}

	return dst, nil
}

// netflowV5SamplerRate resolves the sampler a record names in the second pad
// field. The format reserves those two bytes, and a Cisco router sampling its
// main cache writes the sampler's export id there while leaving the header's
// own sampling field zero -- so the identifier reaches a collector and the
// rate never does. Resolving it against the device's table settles nothing on
// v5, which has no options record to declare with, and the domain counts the
// record as uncorrected instead.
//
// A device at its domain budget loses that accounting rather than the record.
func netflowV5SamplerRate(domain *domainState, samplerID uint32) uint32 {
	if domain == nil || samplerID == unsampledSamplerID {
		return 0
	}

	rate, owed := domain.correctionFor(samplerID, true)
	if owed {
		domain.samplingUnresolved.Add(1)
	}
	return rate
}

// netflowV5Record reads one 48-byte record. The slice is at least that long,
// which decodeNetFlowV5 has established.
func netflowV5Record(
	exporter netip.Addr, record []byte, clock exportClock, samplingRate uint32, domain *domainState,
) flow.Record {
	start, end, ok := clock.anchorPair(
		binary.BigEndian.Uint32(record[24:28]), binary.BigEndian.Uint32(record[28:32]))
	domain.countClockPair(!ok)

	if samplingRate == 0 {
		samplingRate = netflowV5SamplerRate(domain, uint32(binary.BigEndian.Uint16(record[46:48])))
	}

	return flow.Record{
		Exporter: exporter,
		Version:  flow.VersionNetFlowV5,

		SrcAddr: netip.AddrFrom4([4]byte(record[0:4])),
		DstAddr: netip.AddrFrom4([4]byte(record[4:8])),
		SrcPort: binary.BigEndian.Uint16(record[32:34]),
		DstPort: binary.BigEndian.Uint16(record[34:36]),

		Protocol:         record[38],
		TOS:              record[39],
		TOSReported:      true,
		TCPFlags:         record[37],
		TCPFlagsReported: true,

		InputIf:  uint32(binary.BigEndian.Uint16(record[12:14])),
		OutputIf: uint32(binary.BigEndian.Uint16(record[14:16])),

		Packets:       uint64(binary.BigEndian.Uint32(record[16:20])),
		Bytes:         uint64(binary.BigEndian.Uint32(record[20:24])),
		BytesReported: true,
		Flows:         1,

		SrcAS: uint32(binary.BigEndian.Uint16(record[40:42])),
		DstAS: uint32(binary.BigEndian.Uint16(record[42:44])),

		SrcMask: record[44],
		DstMask: record[45],

		Start: start,
		End:   end,

		SamplingRate: samplingRate,
	}
}
