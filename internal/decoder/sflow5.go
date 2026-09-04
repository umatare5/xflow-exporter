// This file parses sFlow v5 flow samples. sFlow ships sampled packet headers
// rather than flow state, so each readable flow record decodes into one
// single-packet record and the aggregator scales it by the sample's own rate.

package decoder

import (
	"encoding/binary"
	"math"
	"net/netip"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	// sFlow agent address types.
	sflowAddrIPv4 = 1
	sflowAddrIPv6 = 2

	// Sample formats of enterprise 0. Counter samples carry interface
	// statistics rather than traffic and are out of scope.
	sflowFlowSample         = 1
	sflowCounterSample      = 2
	sflowFlowSampleExpanded = 3
	sflowCounterExpanded    = 4

	// Flow record formats of enterprise 0.
	sflowRawPacketHeader = 1
	sflowSampledIPv4     = 3
	sflowSampledIPv6     = 4

	// Header protocols of the raw packet header record.
	sflowHeaderEthernet = 1

	// An interface is a format and a value. Only format 0 carries an
	// ifIndex; 1 is a discard reason and 2 a destination count. The
	// compact encoding packs the format into the top two bits, while the
	// expanded encoding spells the two out as separate words.
	sflowIfFormatShift = 30
	sflowIfValueMask   = 0x3FFF_FFFF
)

// sflowIfIndex reads an interface word pair as an ifIndex. Value
// sflowIfValueMask under format 0 marks the agent itself as the source or
// sink, and a non-zero format names something that is not an interface at
// all; both fold to 0, which spells "no interface".
func sflowIfIndex(format, value uint32) uint32 {
	if format != 0 || value == sflowIfValueMask {
		return 0
	}
	return value
}

// decodeSFlowV5 parses one sFlow v5 datagram. A sample this exporter cannot
// read is skipped over its declared length; only a structure whose lengths
// lie is fatal to the datagram.
func (d *Decoder) decodeSFlowV5(
	exporter netip.Addr, payload []byte, dst []flow.Record, issue func(reason string),
) ([]flow.Record, *decodeError) {
	r := newByteReader(payload)

	// Version was sniffed; skip it and read the agent address.
	r.skip(4)
	addrType, _ := r.uint32()
	switch addrType {
	case sflowAddrIPv4:
		r.skip(4)
	case sflowAddrIPv6:
		r.skip(16)
	default:
		return dst, malformed("sflow agent address type %d is neither IPv4 nor IPv6", addrType)
	}

	subAgentID, _ := r.uint32()
	sequence, _ := r.uint32()
	r.skip(4) // uptime
	numSamples, ok := r.uint32()
	if !ok {
		return dst, malformed("sflow datagram of %d bytes ends inside its header", len(payload))
	}

	domain := d.templates.domain(domainKey{exporter: exporter, odid: subAgentID, proto: flow.VersionSFlowV5})
	if domain == nil {
		issue(ReasonDomainLimit)
		return dst, nil
	}
	domain.trackSequence(sequence)

	for range numSamples {
		sampleType, okType := r.uint32()
		sampleLen, okLen := r.uint32()
		if !okType || !okLen {
			return dst, malformed("sflow datagram ends inside a sample header")
		}
		sample, okBody := r.take(int(sampleLen))
		if !okBody {
			return dst, malformed("sflow sample of %d bytes runs past the datagram", sampleLen)
		}

		dst = d.decodeSFlowSample(exporter, sampleType, sample, dst, issue)
	}

	return dst, nil
}

// decodeSFlowSample routes one sample by its type. The enterprise bits are
// the top 20 bits of the type word; only enterprise 0 is standard.
func (d *Decoder) decodeSFlowSample(
	exporter netip.Addr, sampleType uint32, sample []byte, dst []flow.Record, issue func(reason string),
) []flow.Record {
	const formatMask = 0xFFF

	if sampleType>>12 != 0 {
		// A vendor sample; its length told us how to skip it.
		return dst
	}

	switch sampleType & formatMask {
	case sflowFlowSample:
		return d.decodeSFlowFlowSample(exporter, sample, false, dst, issue)
	case sflowFlowSampleExpanded:
		return d.decodeSFlowFlowSample(exporter, sample, true, dst, issue)
	case sflowCounterSample, sflowCounterExpanded:
		// Interface counters, out of scope by design.
		return dst
	default:
		return dst
	}
}

// decodeSFlowFlowSample reads one flow sample and appends one record per
// header record it can decode.
func (d *Decoder) decodeSFlowFlowSample(
	exporter netip.Addr, sample []byte, expanded bool, dst []flow.Record, issue func(reason string),
) []flow.Record {
	r := newByteReader(sample)

	r.skip(4) // sample sequence number
	if expanded {
		r.skip(8) // source id type + index
	} else {
		r.skip(4) // packed source id
	}
	samplingRate, _ := r.uint32()
	r.skip(8) // sample pool, drops

	var inputIf, outputIf uint32
	if expanded {
		inFormat, _ := r.uint32()
		inValue, _ := r.uint32()
		outFormat, _ := r.uint32()
		outValue, _ := r.uint32()
		inputIf = sflowIfIndex(inFormat, inValue)
		outputIf = sflowIfIndex(outFormat, outValue)
	} else {
		in, _ := r.uint32()
		out, _ := r.uint32()
		inputIf = sflowIfIndex(in>>sflowIfFormatShift, in&sflowIfValueMask)
		outputIf = sflowIfIndex(out>>sflowIfFormatShift, out&sflowIfValueMask)
	}

	numRecords, ok := r.uint32()
	if !ok {
		issue(ReasonMalformed)
		return dst
	}

	for range numRecords {
		recordType, okType := r.uint32()
		recordLen, okLen := r.uint32()
		if !okType || !okLen {
			issue(ReasonMalformed)
			return dst
		}
		record, okBody := r.take(int(recordLen))
		if !okBody {
			issue(ReasonMalformed)
			return dst
		}

		dst = d.appendSFlowRecord(exporter, recordType, record, samplingRate, inputIf, outputIf, dst, issue)
	}

	return dst
}

// appendSFlowRecord decodes one flow record where a format this exporter
// reads carries the packet; other formats were skipped by their length.
func (d *Decoder) appendSFlowRecord(
	exporter netip.Addr, recordType uint32, record []byte,
	samplingRate, inputIf, outputIf uint32, dst []flow.Record, issue func(reason string),
) []flow.Record {
	const formatMask = 0xFFF

	if recordType>>12 != 0 {
		return dst
	}

	var read func([]byte, *flow.Record) bool
	switch recordType & formatMask {
	case sflowRawPacketHeader:
		read = readSFlowRawHeader
	case sflowSampledIPv4:
		read = readSFlowSampledIPv4
	case sflowSampledIPv6:
		read = readSFlowSampledIPv6
	default:
		// An extended-data record annotates the sample rather than carrying
		// the packet; skipping it is the design, not a failure.
		return dst
	}

	dst = append(dst, flow.Record{
		Exporter:     exporter,
		Version:      flow.VersionSFlowV5,
		Flows:        1,
		Packets:      1,
		SamplingRate: samplingRate,
		InputIf:      inputIf,
		OutputIf:     outputIf,
	})

	// A record of a known format that does not parse is a structure problem
	// the operator must see, not a silent drop.
	if !read(record, &dst[len(dst)-1]) {
		issue(ReasonMalformed)
		return dst[:len(dst)-1]
	}
	return dst
}

// readSFlowRawHeader decodes the sampled raw packet header record: the frame
// length and the leading bytes of the frame itself.
func readSFlowRawHeader(record []byte, r *flow.Record) bool {
	br := newByteReader(record)

	headerProtocol, _ := br.uint32()
	frameLength, _ := br.uint32()
	br.skip(4) // stripped bytes
	headerLen, ok := br.uint32()
	if !ok || headerProtocol != sflowHeaderEthernet {
		return false
	}
	header, ok := br.take(int(headerLen))
	if !ok {
		return false
	}

	r.Bytes = uint64(frameLength)
	return readEthernetFrame(header, r)
}

// sampledFieldsFit reports whether the words a sampled record narrows can be
// held by what they narrow to. XDR gives each of them a 32-bit word because it
// has no smaller unsigned type, not because the field is that wide, so a value
// past its own range is a nonconformant export rather than a wide spelling of
// one. Truncating it would publish a protocol, a port, a class or a
// control-bit profile no device sent, and the record's byte count is no more
// trustworthy than the rest of it -- so the whole record is refused, which the
// caller counts.
func sampledFieldsFit(protocol, srcPort, dstPort, tcpFlags, tos uint32) bool {
	return protocol <= math.MaxUint8 &&
		srcPort <= math.MaxUint16 &&
		dstPort <= math.MaxUint16 &&
		tcpFlags <= math.MaxUint8 &&
		tos <= math.MaxUint8
}

// readSFlowSampledIPv4 decodes the pre-parsed IPv4 record some devices send
// instead of a raw header.
func readSFlowSampledIPv4(record []byte, r *flow.Record) bool {
	br := newByteReader(record)

	length, _ := br.uint32()
	protocol, _ := br.uint32()
	src, okSrc := br.take(4)
	dstAddr, okDst := br.take(4)
	srcPort, _ := br.uint32()
	dstPort, _ := br.uint32()
	tcpFlags, _ := br.uint32()
	tos, ok := br.uint32()
	if !okSrc || !okDst || !ok {
		return false
	}
	if !sampledFieldsFit(protocol, srcPort, dstPort, tcpFlags, tos) {
		return false
	}

	r.Bytes = uint64(length)
	r.Protocol = uint8(protocol) //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.SrcPort = uint16(srcPort)  //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.DstPort = uint16(dstPort)  //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.TCPFlags = uint8(tcpFlags) //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.TCPFlagsReported = true
	r.TOS = uint8(tos) //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.TOSReported = true
	r.SrcAddr = netip.AddrFrom4([4]byte(src))
	r.DstAddr = netip.AddrFrom4([4]byte(dstAddr))
	return true
}

// readSFlowSampledIPv6 decodes the pre-parsed IPv6 record.
func readSFlowSampledIPv6(record []byte, r *flow.Record) bool {
	br := newByteReader(record)

	length, _ := br.uint32()
	protocol, _ := br.uint32()
	src, okSrc := br.take(16)
	dstAddr, okDst := br.take(16)
	srcPort, _ := br.uint32()
	dstPort, _ := br.uint32()
	tcpFlags, _ := br.uint32()
	priority, ok := br.uint32()
	if !okSrc || !okDst || !ok {
		return false
	}
	if !sampledFieldsFit(protocol, srcPort, dstPort, tcpFlags, priority) {
		return false
	}

	r.Bytes = uint64(length)
	r.Protocol = uint8(protocol) //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.SrcPort = uint16(srcPort)  //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.DstPort = uint16(dstPort)  //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.TCPFlags = uint8(tcpFlags) //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.TCPFlagsReported = true
	r.TOS = uint8(priority) //nolint:gosec // sampledFieldsFit bounded this above; gosec does not follow the call.
	r.TOSReported = true
	r.SrcAddr = addrFrom16([16]byte(src))
	r.DstAddr = addrFrom16([16]byte(dstAddr))
	return true
}

// byteReader is a bounds-checked cursor over one buffer. Every read reports
// whether it fit, so a truncated structure can never read past its bytes.
type byteReader struct {
	buf []byte
	off int
}

func newByteReader(buf []byte) *byteReader {
	return &byteReader{buf: buf}
}

// uint32 reads one big-endian word.
func (r *byteReader) uint32() (uint32, bool) {
	if r.off+4 > len(r.buf) {
		r.off = len(r.buf)
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.buf[r.off : r.off+4])
	r.off += 4
	return v, true
}

// take returns the next n bytes.
func (r *byteReader) take(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.buf) {
		r.off = len(r.buf)
		return nil, false
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b, true
}

// skip advances past n bytes, clamping at the end.
func (r *byteReader) skip(n int) {
	r.off += n
	if r.off > len(r.buf) {
		r.off = len(r.buf)
	}
}
