package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

var testExporter = netip.MustParseAddr("192.0.2.1")

// v5Header fixture values, chosen so every derived quantity is distinct.
const (
	fixtureSysUptimeMs = 60_000
	fixtureExportSecs  = 1_756_200_000
	fixtureExportNanos = 500_000_000
	fixtureSampling    = 100
)

// buildV5Header writes a v5 header claiming count records.
func buildV5Header(count int) []byte {
	header := make([]byte, netflowV5HeaderLen)
	binary.BigEndian.PutUint16(header[0:2], 5)
	binary.BigEndian.PutUint16(header[2:4], uint16(count))
	binary.BigEndian.PutUint32(header[4:8], fixtureSysUptimeMs)
	binary.BigEndian.PutUint32(header[8:12], fixtureExportSecs)
	binary.BigEndian.PutUint32(header[12:16], fixtureExportNanos)
	binary.BigEndian.PutUint32(header[16:20], 42) // flow_sequence
	header[20] = 0                                // engine_type
	header[21] = 1                                // engine_id
	binary.BigEndian.PutUint16(header[22:24], fixtureSampling)
	return header
}

// buildV5Record writes one 48-byte record. Every field carries a distinct
// value so a parser reading a neighboring offset reports another number.
func buildV5Record() []byte {
	record := make([]byte, netflowV5RecordLen)
	copy(record[0:4], []byte{10, 0, 0, 1})            // srcaddr
	copy(record[4:8], []byte{198, 51, 100, 7})        // dstaddr
	copy(record[8:12], []byte{10, 0, 0, 254})         // nexthop
	binary.BigEndian.PutUint16(record[12:14], 3)      // input
	binary.BigEndian.PutUint16(record[14:16], 4)      // output
	binary.BigEndian.PutUint32(record[16:20], 1000)   // dPkts
	binary.BigEndian.PutUint32(record[20:24], 512000) // dOctets
	binary.BigEndian.PutUint32(record[24:28], 30_000) // first (uptime ms)
	binary.BigEndian.PutUint32(record[28:32], 45_000) // last (uptime ms)
	binary.BigEndian.PutUint16(record[32:34], 51234)  // srcport
	binary.BigEndian.PutUint16(record[34:36], 443)    // dstport
	record[36] = 0                                    // pad1
	record[37] = 0x1B                                 // tcp_flags
	record[38] = 6                                    // prot
	record[39] = 0xB8                                 // tos
	binary.BigEndian.PutUint16(record[40:42], 64500)  // src_as
	binary.BigEndian.PutUint16(record[42:44], 64501)  // dst_as
	record[44] = 24                                   // src_mask
	record[45] = 25                                   // dst_mask
	return record
}

// buildV5Packet assembles a datagram of n copies of the fixture record.
func buildV5Packet(n int) []byte {
	payload := buildV5Header(n)
	for range n {
		payload = append(payload, buildV5Record()...)
	}
	return payload
}

// decodeV5 reads one datagram through a decoder of its own, so a parse test
// reads the record rather than the domain a shared decoder carries forward.
func decodeV5(payload []byte) ([]flow.Record, *decodeError) {
	return newTestDecoder().decodeNetFlowV5(testExporter, payload, nil, func(string) {})
}

func TestDecodeNetFlowV5_ReadsEveryField(t *testing.T) {
	t.Parallel()

	records, decErr := decodeV5(buildV5Packet(1))
	if decErr != nil {
		t.Fatalf("decodeNetFlowV5() error = %v, want nil", decErr)
	}
	if len(records) != 1 {
		t.Fatalf("decodeNetFlowV5() returned %d records, want 1", len(records))
	}

	got := records[0]
	bootTime := time.Unix(fixtureExportSecs, fixtureExportNanos).
		Add(-fixtureSysUptimeMs * time.Millisecond)

	want := flow.Record{
		Exporter:         testExporter,
		Version:          flow.VersionNetFlowV5,
		SrcAddr:          netip.MustParseAddr("10.0.0.1"),
		DstAddr:          netip.MustParseAddr("198.51.100.7"),
		SrcPort:          51234,
		DstPort:          443,
		Protocol:         6,
		TOS:              0xB8,
		TOSReported:      true,
		TCPFlags:         0x1B,
		TCPFlagsReported: true,
		InputIf:          3,
		OutputIf:         4,
		Bytes:            512000,
		Packets:          1000,
		BytesReported:    true,
		Flows:            1,
		SrcAS:            64500,
		DstAS:            64501,
		SrcMask:          24,
		DstMask:          25,
		Start:            bootTime.Add(30_000 * time.Millisecond),
		End:              bootTime.Add(45_000 * time.Millisecond),
		SamplingRate:     fixtureSampling,
	}

	if got != want {
		t.Errorf("decodeNetFlowV5() record =\n%+v\nwant\n%+v", got, want)
	}

	duration, ok := got.Duration()
	if !ok || duration != 15*time.Second {
		t.Errorf("Duration() = %v, %v, want 15s, true", duration, ok)
	}
}

func TestDecodeNetFlowV5_ReadsEveryClaimedRecord(t *testing.T) {
	t.Parallel()

	records, decErr := decodeV5(buildV5Packet(netflowV5MaxCount))
	if decErr != nil {
		t.Fatalf("decodeNetFlowV5() error = %v, want nil", decErr)
	}
	if len(records) != netflowV5MaxCount {
		t.Errorf("decodeNetFlowV5() returned %d records, want %d", len(records), netflowV5MaxCount)
	}
}

func TestDecodeNetFlowV5_ToleratesTrailingPadding(t *testing.T) {
	t.Parallel()

	payload := append(buildV5Packet(2), 0, 0, 0, 0)

	records, decErr := decodeV5(payload)
	if decErr != nil {
		t.Fatalf("decodeNetFlowV5() error = %v, want padding tolerated", decErr)
	}
	if len(records) != 2 {
		t.Errorf("decodeNetFlowV5() returned %d records, want 2", len(records))
	}
}

func TestDecodeNetFlowV5_SamplingModeBitsAreMasked(t *testing.T) {
	t.Parallel()

	payload := buildV5Packet(1)
	// Set the two mode bits above a 14-bit interval of 512.
	binary.BigEndian.PutUint16(payload[22:24], 0x8000|512)

	records, decErr := decodeV5(payload)
	if decErr != nil {
		t.Fatalf("decodeNetFlowV5() error = %v, want nil", decErr)
	}
	if records[0].SamplingRate != 512 {
		t.Errorf("SamplingRate = %d, want the mode bits masked off 512", records[0].SamplingRate)
	}
}

func TestDecodeNetFlowV5_RejectsMalformedDatagrams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "header cut short",
			payload: buildV5Header(1)[:20],
		},
		{
			name:    "zero record count",
			payload: buildV5Packet(0),
		},
		{
			name: "count above the format maximum",
			payload: func() []byte {
				p := buildV5Packet(1)
				binary.BigEndian.PutUint16(p[2:4], netflowV5MaxCount+1)
				return p
			}(),
		},
		{
			name:    "payload shorter than the claimed records",
			payload: buildV5Packet(3)[:netflowV5HeaderLen+2*netflowV5RecordLen],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			records, decErr := decodeV5(tt.payload)
			if decErr == nil {
				t.Fatal("decodeNetFlowV5() error = nil, want a malformed rejection")
			}
			if decErr.Reason() != ReasonMalformed {
				t.Errorf("Reason() = %q, want %q", decErr.Reason(), ReasonMalformed)
			}
			if len(records) != 0 {
				t.Errorf("decodeNetFlowV5() returned %d records alongside the error, want 0", len(records))
			}
		})
	}
}

func BenchmarkDecodeNetFlowV5(b *testing.B) {
	d := newTestDecoder()
	payload := buildV5Packet(netflowV5MaxCount)
	records := make([]flow.Record, 0, netflowV5MaxCount)
	noIssue := func(string) {}

	b.ReportAllocs()
	for b.Loop() {
		var err *decodeError
		records, err = d.decodeNetFlowV5(testExporter, payload, records[:0], noIssue)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// v5Sequence stamps a datagram's sequence and switching engine, the two header
// fields the export sequence is numbered within.
func v5Sequence(payload []byte, seq uint32, engine uint16) []byte {
	binary.BigEndian.PutUint32(payload[16:20], seq)
	binary.BigEndian.PutUint16(payload[20:22], engine)
	return payload
}

// TestDecodeNetFlowV5_SequenceCountsRecords pins the unit the v5 sequence
// counts. The number is a running record count, so reading it as the packet
// count v9 carries turns every datagram of more than one record into loss.
func TestDecodeNetFlowV5_SequenceCountsRecords(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// Ten records over two datagrams of five, so the next is expected at 20.
	// A third claiming 25 says the five from 20 never arrived.
	for _, seq := range []uint32{10, 15} {
		if _, err := d.Decode(testExporter, v5Sequence(buildV5Packet(5), seq, 0), nil); err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
	}
	if got := d.Domains()[0].SequenceMissed; got != 0 {
		t.Fatalf("SequenceMissed = %d after an unbroken run of five-record datagrams, want 0", got)
	}

	if _, err := d.Decode(testExporter, v5Sequence(buildV5Packet(5), 25, 0), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if got := d.Domains()[0].SequenceMissed; got != 5 {
		t.Errorf("SequenceMissed = %d, want the 5 records the gap names", got)
	}
}

// TestDecodeNetFlowV5_SequencePerSwitchingEngine pins what a device with more
// than one switching engine reads as. Each engine numbers its own sequence and
// the v5 header carries no domain to key them apart, so the arrivals interleave
// and counting their steps would report loss on a device losing nothing.
func TestDecodeNetFlowV5_SequencePerSwitchingEngine(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	for _, step := range []struct {
		seq    uint32
		engine uint16
	}{{100, 0x0000}, {7000, 0x0001}, {105, 0x0000}, {7005, 0x0001}} {
		if _, err := d.Decode(testExporter, v5Sequence(buildV5Packet(5), step.seq, step.engine), nil); err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
	}

	if got := d.Domains()[0].SequenceMissed; got != 0 {
		t.Errorf("SequenceMissed = %d from two engines taking turns, want 0", got)
	}
}
