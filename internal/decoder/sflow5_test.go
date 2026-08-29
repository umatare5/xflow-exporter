package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// sflowDatagram assembles one sFlow v5 datagram with an IPv4 agent.
func sflowDatagram(sequence uint32, samples ...[]byte) []byte {
	p := be32(nil, 5)                 // version
	p = be32(p, sflowAddrIPv4)        // agent address type
	p = append(p, 192, 0, 2, 50)      // agent address
	p = be32(p, 7)                    // sub agent id
	p = be32(p, sequence)             // datagram sequence
	p = be32(p, 555_000)              // uptime ms
	p = be32(p, uint32(len(samples))) // sample count
	for _, s := range samples {
		p = append(p, s...)
	}
	return p
}

// sflowSample wraps a body as one sample.
func sflowSample(sampleType uint32, body []byte) []byte {
	p := be32(nil, sampleType)
	p = be32(p, uint32(len(body)))
	return append(p, body...)
}

// sflowFlowSampleBody builds a compact flow sample holding records.
func sflowFlowSampleBody(samplingRate, input, output uint32, records ...[]byte) []byte {
	p := be32(nil, 900)      // sample sequence
	p = be32(p, 0x01_000003) // source id
	p = be32(p, samplingRate)
	p = be32(p, 1_000_000) // sample pool
	p = be32(p, 2)         // drops
	p = be32(p, input)
	p = be32(p, output)
	p = be32(p, uint32(len(records)))
	for _, r := range records {
		p = append(p, r...)
	}
	return p
}

// sflowRecord wraps a body as one flow record.
func sflowRecord(recordType uint32, body []byte) []byte {
	p := be32(nil, recordType)
	p = be32(p, uint32(len(body)))
	return append(p, body...)
}

// tcpFrame builds an Ethernet/IPv4/TCP header, optionally VLAN-tagged.
func tcpFrame(vlan bool) []byte {
	f := make([]byte, 0, 64)
	// dst mac, src mac
	f = append(f, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
	if vlan {
		f = be16(f, etherTypeVLAN)
		f = be16(f, 100) // VLAN 100
	}
	f = be16(f, etherTypeIPv4)

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[1] = 0xB8 // tos
	ip[9] = protocolTCP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{198, 51, 100, 7})
	f = append(f, ip...)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 51234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[13] = 0x18 // PSH|ACK
	f = append(f, tcp...)
	return f
}

// rawHeaderRecord wraps a frame in a raw packet header record.
func rawHeaderRecord(frame []byte, frameLength uint32) []byte {
	body := be32(nil, sflowHeaderEthernet)
	body = be32(body, frameLength)
	body = be32(body, 4) // stripped
	body = be32(body, uint32(len(frame)))
	body = append(body, frame...)
	return sflowRecord(sflowRawPacketHeader, body)
}

func TestDecodeSFlowV5_RawEthernetTCP(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(1000, 3, 4, rawHeaderRecord(tcpFrame(false), 1518))))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}

	want := flow.Record{
		Exporter:         testExporter,
		Version:          flow.VersionSFlowV5,
		SrcAddr:          netip.MustParseAddr("10.0.0.1"),
		DstAddr:          netip.MustParseAddr("198.51.100.7"),
		SrcPort:          51234,
		DstPort:          443,
		Protocol:         protocolTCP,
		TOS:              0xB8,
		TOSReported:      true,
		TCPFlags:         0x18,
		TCPFlagsReported: true,
		InputIf:          3,
		OutputIf:         4,
		Bytes:            1518,
		Packets:          1,
		Flows:            1,
		SamplingRate:     1000,
	}
	if records[0] != want {
		t.Errorf("Decode() record =\n%+v\nwant\n%+v", records[0], want)
	}
}

func TestDecodeSFlowV5_VLANTaggedFrame(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(500, 1, 2, rawHeaderRecord(tcpFrame(true), 900))))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	if records[0].SrcPort != 51234 || records[0].DstPort != 443 {
		t.Errorf("record = %+v, want the ports read through the VLAN tag", records[0])
	}
}

func TestDecodeSFlowV5_ExpandedSample(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	body := be32(nil, 900)  // sequence
	body = be32(body, 0)    // source id type
	body = be32(body, 3)    // source id index
	body = be32(body, 2000) // sampling rate
	body = be32(body, 5000) // pool
	body = be32(body, 0)    // drops
	body = be32(body, 0)    // input format
	body = be32(body, 13)   // input value
	body = be32(body, 0)    // output format
	body = be32(body, 14)   // output value
	body = be32(body, 1)    // record count
	body = append(body, rawHeaderRecord(tcpFrame(false), 1200)...)

	datagram := sflowDatagram(1, sflowSample(sflowFlowSampleExpanded, body))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	got := records[0]
	if got.SamplingRate != 2000 || got.InputIf != 13 || got.OutputIf != 14 || got.Bytes != 1200 {
		t.Errorf("record = %+v, want the expanded sample fields applied", got)
	}
}

func TestDecodeSFlowV5_SampledIPv4Record(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	body := be32(nil, 700)         // length
	body = be32(body, protocolUDP) // protocol
	body = append(body, 10, 0, 0, 9, 10, 0, 0, 10)
	body = be32(body, 53000)
	body = be32(body, 53)
	body = be32(body, 0)    // tcp flags
	body = be32(body, 0x10) // tos

	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(100, 1, 2, sflowRecord(sflowSampledIPv4, body))))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	// Compared whole rather than field by field: the presence bits this
	// reader sets are the only thing standing between a device that reports a
	// class and one that does not, and a field-by-field check reads past them.
	want := flow.Record{
		Exporter:         testExporter,
		Version:          flow.VersionSFlowV5,
		SrcAddr:          netip.MustParseAddr("10.0.0.9"),
		DstAddr:          netip.MustParseAddr("10.0.0.10"),
		SrcPort:          53000,
		DstPort:          53,
		Protocol:         protocolUDP,
		TOS:              0x10,
		TOSReported:      true,
		TCPFlagsReported: true,
		InputIf:          1,
		OutputIf:         2,
		Bytes:            700,
		Packets:          1,
		Flows:            1,
		SamplingRate:     100,
	}
	if got := records[0]; got != want {
		t.Errorf("record = %+v, want %+v", got, want)
	}
}

func TestDecodeSFlowV5_SampledIPv6RecordUnmapsIPv4(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	body := be32(nil, 700)
	body = be32(body, protocolUDP)
	body = append(body, netip.MustParseAddr("::ffff:10.0.0.9").AsSlice()...)
	body = append(body, netip.MustParseAddr("::ffff:10.0.0.10").AsSlice()...)
	body = be32(body, 53000)
	body = be32(body, 53)
	body = be32(body, 0)    // tcp flags
	body = be32(body, 0x10) // priority

	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(100, 1, 2, sflowRecord(sflowSampledIPv6, body))))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	want := flow.Record{
		Exporter:         testExporter,
		Version:          flow.VersionSFlowV5,
		SrcAddr:          netip.MustParseAddr("10.0.0.9"),
		DstAddr:          netip.MustParseAddr("10.0.0.10"),
		SrcPort:          53000,
		DstPort:          53,
		Protocol:         protocolUDP,
		TOS:              0x10,
		TOSReported:      true,
		TCPFlagsReported: true,
		InputIf:          1,
		OutputIf:         2,
		Bytes:            700,
		Packets:          1,
		Flows:            1,
		SamplingRate:     100,
	}
	if got := records[0]; got != want {
		t.Errorf("record = %+v, want %+v", got, want)
	}
}

func TestDecodeSFlowV5_RawIPv6HeaderUnmapsIPv4(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(10, 1, 2, rawHeaderRecord(mappedIPv6Frame(), 128))))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	if got := records[0].SrcAddr; got != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("SrcAddr = %v, want the unmapped 192.0.2.10", got)
	}
	if got := records[0].DstAddr; got != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("DstAddr = %v, want the unmapped 198.51.100.7", got)
	}
}

// mappedIPv6Frame is an Ethernet frame whose IPv6 header carries IPv4-mapped
// addresses, which a translating device on the sampled path produces.
func mappedIPv6Frame() []byte {
	f := make([]byte, 0, 78)
	f = append(f, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
	f = be16(f, etherTypeIPv6)

	ip := make([]byte, ipv6HdrLen)
	ip[0] = 0x60 // version 6
	ip[6] = protocolTCP
	copy(ip[8:24], netip.MustParseAddr("::ffff:192.0.2.10").AsSlice())
	copy(ip[24:40], netip.MustParseAddr("::ffff:198.51.100.7").AsSlice())
	f = append(f, ip...)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 51234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	return append(f, tcp...)
}

func TestDecodeSFlowV5_CounterSampleYieldsNothing(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	datagram := sflowDatagram(1,
		sflowSample(sflowCounterSample, make([]byte, 32)),
		sflowSample(sflowFlowSample,
			sflowFlowSampleBody(10, 1, 2, rawHeaderRecord(tcpFrame(false), 64))),
	)

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the counter sample skipped", err)
	}
	if len(records) != 1 {
		t.Errorf("Decode() returned %d records, want 1 from the flow sample alone", len(records))
	}
}

func TestDecodeSFlowV5_TruncatedHeaderKeepsWhatDecoded(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// The sampled header covers Ethernet and IPv4 but cuts before the ports.
	frame := tcpFrame(false)[:ethernetHdrLen+ipv4MinHdrLen]

	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(10, 1, 2, rawHeaderRecord(frame, 1518))))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	got := records[0]
	if !got.SrcAddr.IsValid() || got.Protocol != protocolTCP {
		t.Errorf("record = %+v, want the network layer kept", got)
	}
	if got.SrcPort != 0 || got.DstPort != 0 {
		t.Errorf("record = %+v, want the ports absent rather than misread", got)
	}
}

func TestDecodeSFlowV5_UnreadableKnownRecordIsCounted(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// A sampled-IPv4 record four bytes short of its fixed layout.
	short := sflowRecord(sflowSampledIPv4, make([]byte, 28))
	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(10, 1, 2, short)))

	records, err := d.Decode(testExporter, datagram, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the datagram tolerated", err)
	}
	if len(records) != 0 {
		t.Errorf("Decode() returned %d records, want 0 from the unreadable record", len(records))
	}
	if got := errorCountFor(d, flow.VersionSFlowV5, ReasonMalformed); got != 1 {
		t.Errorf("malformed count = %d, want 1", got)
	}
}

func TestDecodeSFlowV5_RejectsBrokenStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "header cut short",
			payload: sflowDatagram(1)[:16],
		},
		{
			name:    "unknown agent address type",
			payload: append(be32(be32(nil, 5), 9), make([]byte, 20)...),
		},
		{
			name: "sample running past the datagram",
			payload: func() []byte {
				p := sflowDatagram(1, sflowSample(sflowFlowSample, make([]byte, 8)))
				// Inflate the declared sample length beyond the datagram.
				binary.BigEndian.PutUint32(p[32:36], 5000)
				return p
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			records, err := d.Decode(testExporter, tt.payload, nil)
			if err == nil {
				t.Fatal("Decode() error = nil, want a malformed rejection")
			}
			if len(records) != 0 {
				t.Errorf("Decode() returned %d records alongside the error, want 0", len(records))
			}
		})
	}
}

func TestDecodeSFlowV5_SequencePerSubAgent(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	for _, seq := range []uint32{1, 2, 6} {
		if _, err := d.Decode(testExporter, sflowDatagram(seq), nil); err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
	}

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d domains, want 1 keyed by the sub-agent", len(domains))
	}
	if domains[0].ODID != 7 {
		t.Errorf("ODID = %d, want the sub-agent id 7", domains[0].ODID)
	}
	if domains[0].SequenceMissed != 3 {
		t.Errorf("SequenceMissed = %d, want 3", domains[0].SequenceMissed)
	}
}

func BenchmarkDecodeSFlowV5(b *testing.B) {
	d := newTestDecoder()

	records := make([][]byte, 0, 8)
	for range 8 {
		records = append(records, rawHeaderRecord(tcpFrame(false), 1518))
	}
	datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(1000, 3, 4, records...)))
	dst := make([]flow.Record, 0, 8)

	b.ReportAllocs()
	for b.Loop() {
		var err error
		dst, err = d.Decode(testExporter, datagram, dst[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// fragmentFrame is tcpFrame's packet carried as a later fragment, so the
// bytes where a transport header would sit are application payload.
func fragmentFrame(fragWord uint16) []byte {
	f := tcpFrame(false)
	// The IPv4 header starts past the 14-byte Ethernet header, and the
	// flags-and-offset word is at its bytes 6 and 7.
	binary.BigEndian.PutUint16(f[14+6:14+8], fragWord)
	return f
}

// TestDecodeSFlowV5_LaterFragmentReportsNoTransport is the regression test for
// ports and control bits read out of application payload. A fragment past the
// first carries no transport header, and the walk read one anyway -- so a
// fabricated port pair reached xflow_destination_* and a fabricated profile
// reached xflow_tcp_flags_*, including the flags="none" an operator hunts
// scans with. Fragments are ordinary in tunneled and large-UDP traffic, and a
// sampler picks them up in proportion to their share.
func TestDecodeSFlowV5_LaterFragmentReportsNoTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		fragWord      uint16
		wantTransport bool
	}{
		{name: "first fragment, more to come", fragWord: 0x2000, wantTransport: true},
		{name: "later fragment", fragWord: 0x00B9, wantTransport: false},
		{name: "later fragment, more to come", fragWord: 0x20B9, wantTransport: false},
		{name: "not fragmented, do not fragment", fragWord: 0x4000, wantTransport: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			records, err := d.Decode(testExporter, sflowDatagram(1, sflowSample(sflowFlowSample,
				sflowFlowSampleBody(1000, 3, 4, rawHeaderRecord(fragmentFrame(tt.fragWord), 1518)))), nil)
			if err != nil || len(records) != 1 {
				t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
			}
			got := records[0]

			// The network layer is genuine on every fragment.
			if got.SrcAddr != netip.MustParseAddr("10.0.0.1") || got.Protocol != protocolTCP {
				t.Errorf("SrcAddr = %v, Protocol = %d; want 10.0.0.1, %d", got.SrcAddr, got.Protocol, protocolTCP)
			}
			if !got.TOSReported || got.TOS != 0xB8 {
				t.Errorf("TOS = %#02x reported = %v; want 0xb8, true", got.TOS, got.TOSReported)
			}

			if tt.wantTransport {
				if got.SrcPort != 51234 || got.DstPort != 443 || !got.TCPFlagsReported {
					t.Errorf("ports = %d/%d flags reported = %v; want 51234/443, true",
						got.SrcPort, got.DstPort, got.TCPFlagsReported)
				}
				return
			}
			if got.SrcPort != 0 || got.DstPort != 0 {
				t.Errorf("ports = %d/%d, want 0/0 from payload the fragment does not describe",
					got.SrcPort, got.DstPort)
			}
			if got.TCPFlagsReported {
				t.Errorf("TCPFlagsReported = true, want false: a later fragment carries no control bits")
			}
		})
	}
}

// sampledIPv4Body builds one sampled_ipv4 record body from its eight words.
func sampledIPv4Body(protocol, srcPort, dstPort, tcpFlags, tos uint32) []byte {
	body := be32(nil, 700)
	body = be32(body, protocol)
	body = append(body, 10, 0, 0, 9, 10, 0, 0, 10)
	body = be32(body, srcPort)
	body = be32(body, dstPort)
	body = be32(body, tcpFlags)
	return be32(body, tos)
}

// sampledIPv6Body is the same with sixteen-byte addresses.
func sampledIPv6Body(protocol, srcPort, dstPort, tcpFlags, priority uint32) []byte {
	body := be32(nil, 700)
	body = be32(body, protocol)
	body = append(body, netip.MustParseAddr("2001:db8::9").AsSlice()...)
	body = append(body, netip.MustParseAddr("2001:db8::a").AsSlice()...)
	body = be32(body, srcPort)
	body = be32(body, dstPort)
	body = be32(body, tcpFlags)
	return be32(body, priority)
}

// TestDecodeSFlowV5_SampledRecordRefusesAnOverwideWord is the regression test
// for a narrowing that published what it truncated. XDR gives every one of
// these fields a 32-bit word because it has no smaller unsigned type, so a
// value the field cannot hold is a nonconformant export rather than a wide
// spelling -- and truncating it published a protocol, a port, a class and a
// control-bit profile no device sent, with no error counted. One such record
// keyed flags="none", which is what a NULL scan reads as.
func TestDecodeSFlowV5_SampledRecordRefusesAnOverwideWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		v4    []byte
		v6    []byte
		wants bool
	}{
		{
			name:  "every word fits",
			v4:    sampledIPv4Body(protocolUDP, 53000, 53, 0, 0x10),
			v6:    sampledIPv6Body(protocolUDP, 53000, 53, 0, 0x10),
			wants: true,
		},
		{
			name: "the protocol does not fit",
			v4:   sampledIPv4Body(0x106, 53000, 53, 0, 0x10),
			v6:   sampledIPv6Body(0x106, 53000, 53, 0, 0x10),
		},
		{
			name: "the source port does not fit",
			v4:   sampledIPv4Body(protocolUDP, 0x10050, 53, 0, 0x10),
			v6:   sampledIPv6Body(protocolUDP, 0x10050, 53, 0, 0x10),
		},
		{
			name: "the destination port does not fit",
			v4:   sampledIPv4Body(protocolUDP, 53000, 0x10035, 0, 0x10),
			v6:   sampledIPv6Body(protocolUDP, 53000, 0x10035, 0, 0x10),
		},
		{
			name: "the control bits do not fit",
			v4:   sampledIPv4Body(protocolTCP, 53000, 53, 0x100, 0x10),
			v6:   sampledIPv6Body(protocolTCP, 53000, 53, 0x100, 0x10),
		},
		{
			name: "the class does not fit",
			v4:   sampledIPv4Body(protocolUDP, 53000, 53, 0, 0x1B8),
			v6:   sampledIPv6Body(protocolUDP, 53000, 53, 0, 0x1B8),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, form := range []struct {
				kind uint32
				body []byte
			}{{sflowSampledIPv4, tt.v4}, {sflowSampledIPv6, tt.v6}} {
				d := newTestDecoder()
				records, err := d.Decode(testExporter, sflowDatagram(1, sflowSample(sflowFlowSample,
					sflowFlowSampleBody(100, 1, 2, sflowRecord(form.kind, form.body)))), nil)
				if err != nil {
					t.Fatalf("Decode() error = %v, want nil", err)
				}

				want := 0
				if tt.wants {
					want = 1
				}
				if len(records) != want {
					t.Errorf("format %d: Decode() = %d records, want %d", form.kind, len(records), want)
				}

				var malformed uint64
				for _, e := range d.Stats().Snapshot()[0].Errors {
					if e.Version == flow.VersionSFlowV5 && e.Reason == ReasonMalformed {
						malformed = e.Count
					}
				}
				wantMalformed := uint64(1)
				if tt.wants {
					wantMalformed = 0
				}
				if malformed != wantMalformed {
					t.Errorf("format %d: malformed = %d, want %d so the refusal is visible",
						form.kind, malformed, wantMalformed)
				}
			}
		})
	}
}
