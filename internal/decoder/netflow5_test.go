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

func TestDecodeNetFlowV5_ReadsEveryField(t *testing.T) {
	t.Parallel()

	records, decErr := decodeNetFlowV5(testExporter, buildV5Packet(1), nil)
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
		Exporter:     testExporter,
		Version:      flow.VersionNetFlowV5,
		SrcAddr:      netip.MustParseAddr("10.0.0.1"),
		DstAddr:      netip.MustParseAddr("198.51.100.7"),
		SrcPort:      51234,
		DstPort:      443,
		Protocol:     6,
		TOS:          0xB8,
		TCPFlags:     0x1B,
		InputIf:      3,
		OutputIf:     4,
		Bytes:        512000,
		Packets:      1000,
		SrcAS:        64500,
		DstAS:        64501,
		Start:        bootTime.Add(30_000 * time.Millisecond),
		End:          bootTime.Add(45_000 * time.Millisecond),
		SamplingRate: fixtureSampling,
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

	records, decErr := decodeNetFlowV5(testExporter, buildV5Packet(netflowV5MaxCount), nil)
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

	records, decErr := decodeNetFlowV5(testExporter, payload, nil)
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

	records, decErr := decodeNetFlowV5(testExporter, payload, nil)
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

			records, decErr := decodeNetFlowV5(testExporter, tt.payload, nil)
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
	payload := buildV5Packet(netflowV5MaxCount)
	records := make([]flow.Record, 0, netflowV5MaxCount)

	b.ReportAllocs()
	for b.Loop() {
		var err *decodeError
		records, err = decodeNetFlowV5(testExporter, payload, records[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}
