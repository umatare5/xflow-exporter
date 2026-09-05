package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// buildV8Header writes a v8 header for one aggregation method claiming count
// records, reusing the v5 fixture times so the anchored instants match.
func buildV8Header(aggregation uint8, count int) []byte {
	header := make([]byte, netflowV8HeaderLen)
	binary.BigEndian.PutUint16(header[0:2], 8)
	binary.BigEndian.PutUint16(header[2:4], uint16(count))
	binary.BigEndian.PutUint32(header[4:8], fixtureSysUptimeMs)
	binary.BigEndian.PutUint32(header[8:12], fixtureExportSecs)
	binary.BigEndian.PutUint32(header[12:16], fixtureExportNanos)
	binary.BigEndian.PutUint32(header[16:20], 7) // flow_sequence
	header[20] = 0                               // engine_type
	header[21] = 1                               // engine_id
	header[22] = aggregation
	header[23] = netflowV8AggVersion
	return header
}

// fixtureBootTime is the anchor the v8 header above produces.
func fixtureBootTime() time.Time {
	return time.Unix(fixtureExportSecs, fixtureExportNanos).
		Add(-fixtureSysUptimeMs * time.Millisecond)
}

// The uptime instants every scheme record below carries at the flow-tools
// offsets, ten seconds apart so a swapped read reports another instant.
const (
	fixtureV8FirstMs = 10_000
	fixtureV8LastMs  = 20_000
)

// putV8Common writes the dFlows/dPkts/dOctets/First/Last prefix.
func putV8Common(record []byte) {
	binary.BigEndian.PutUint32(record[0:4], 9)      // dFlows
	binary.BigEndian.PutUint32(record[4:8], 200)    // dPkts
	binary.BigEndian.PutUint32(record[8:12], 90000) // dOctets
	binary.BigEndian.PutUint32(record[12:16], fixtureV8FirstMs)
	binary.BigEndian.PutUint32(record[16:20], fixtureV8LastMs)
}

// baseV8Want is what every common-prefix scheme decodes to before its own
// dimensions are added.
func baseV8Want() flow.Record {
	return flow.Record{
		Exporter:      testExporter,
		Version:       flow.VersionNetFlowV8,
		Flows:         9,
		Packets:       200,
		Bytes:         90000,
		BytesReported: true,
		Start:         fixtureBootTime().Add(fixtureV8FirstMs * time.Millisecond),
		End:           fixtureBootTime().Add(fixtureV8LastMs * time.Millisecond),
	}
}

func TestDecodeNetFlowV8_ReadsEveryScheme(t *testing.T) {
	t.Parallel()

	srcPrefix := netip.MustParseAddr("10.1.0.0")
	dstPrefix := netip.MustParseAddr("10.2.0.0")

	tests := []struct {
		name        string
		aggregation uint8
		record      func() []byte
		want        func() flow.Record
	}{
		{
			name:        "1 AS",
			aggregation: 1,
			record: func() []byte {
				r := make([]byte, 28)
				putV8Common(r)
				binary.BigEndian.PutUint16(r[20:22], 64500)
				binary.BigEndian.PutUint16(r[22:24], 64501)
				binary.BigEndian.PutUint16(r[24:26], 3)
				binary.BigEndian.PutUint16(r[26:28], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAS, w.DstAS, w.InputIf, w.OutputIf = 64500, 64501, 3, 4
				return w
			},
		},
		{
			name:        "2 protocol port",
			aggregation: 2,
			record: func() []byte {
				r := make([]byte, 28)
				putV8Common(r)
				r[20] = 17
				binary.BigEndian.PutUint16(r[24:26], 53000)
				binary.BigEndian.PutUint16(r[26:28], 53)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.Protocol, w.SrcPort, w.DstPort = 17, 53000, 53
				return w
			},
		},
		{
			name:        "3 source prefix",
			aggregation: 3,
			record: func() []byte {
				r := make([]byte, 32)
				putV8Common(r)
				copy(r[20:24], srcPrefix.AsSlice())
				r[24] = 16
				binary.BigEndian.PutUint16(r[26:28], 64500)
				binary.BigEndian.PutUint16(r[28:30], 3)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAddr, w.SrcMask, w.SrcAS, w.InputIf = srcPrefix, 16, 64500, 3
				return w
			},
		},
		{
			name:        "4 destination prefix",
			aggregation: 4,
			record: func() []byte {
				r := make([]byte, 32)
				putV8Common(r)
				copy(r[20:24], dstPrefix.AsSlice())
				r[24] = 17
				binary.BigEndian.PutUint16(r[26:28], 64501)
				binary.BigEndian.PutUint16(r[28:30], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.DstAddr, w.DstMask, w.DstAS, w.OutputIf = dstPrefix, 17, 64501, 4
				return w
			},
		},
		{
			name:        "5 prefix",
			aggregation: 5,
			record: func() []byte {
				r := make([]byte, 40)
				putV8Common(r)
				copy(r[20:24], srcPrefix.AsSlice())
				copy(r[24:28], dstPrefix.AsSlice())
				r[28] = 17
				r[29] = 16
				binary.BigEndian.PutUint16(r[32:34], 64500)
				binary.BigEndian.PutUint16(r[34:36], 64501)
				binary.BigEndian.PutUint16(r[36:38], 3)
				binary.BigEndian.PutUint16(r[38:40], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAddr, w.DstAddr, w.DstMask, w.SrcMask = srcPrefix, dstPrefix, 17, 16
				w.SrcAS, w.DstAS, w.InputIf, w.OutputIf = 64500, 64501, 3, 4
				return w
			},
		},
		{
			name:        "6 destination only",
			aggregation: 6,
			record: func() []byte {
				r := make([]byte, 32)
				copy(r[0:4], dstPrefix.AsSlice())
				binary.BigEndian.PutUint32(r[4:8], 200)
				binary.BigEndian.PutUint32(r[8:12], 90000)
				binary.BigEndian.PutUint32(r[12:16], fixtureV8FirstMs)
				binary.BigEndian.PutUint32(r[16:20], fixtureV8LastMs)
				binary.BigEndian.PutUint16(r[20:22], 4)
				r[22] = 0xB8
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.Flows = 1
				w.DstAddr, w.OutputIf, w.TOS = dstPrefix, 4, 0xB8
				w.TOSReported = true
				return w
			},
		},
		{
			name:        "7 source destination",
			aggregation: 7,
			record: func() []byte {
				r := make([]byte, 40)
				copy(r[0:4], dstPrefix.AsSlice())
				copy(r[4:8], srcPrefix.AsSlice())
				binary.BigEndian.PutUint32(r[8:12], 200)
				binary.BigEndian.PutUint32(r[12:16], 90000)
				binary.BigEndian.PutUint32(r[16:20], fixtureV8FirstMs)
				binary.BigEndian.PutUint32(r[20:24], fixtureV8LastMs)
				binary.BigEndian.PutUint16(r[24:26], 4)
				binary.BigEndian.PutUint16(r[26:28], 3)
				r[28] = 0xB8
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.Flows = 1
				w.DstAddr, w.SrcAddr = dstPrefix, srcPrefix
				w.OutputIf, w.InputIf, w.TOS = 4, 3, 0xB8
				w.TOSReported = true
				return w
			},
		},
		{
			name:        "8 full flow",
			aggregation: 8,
			record: func() []byte {
				r := make([]byte, 44)
				copy(r[0:4], dstPrefix.AsSlice())
				copy(r[4:8], srcPrefix.AsSlice())
				binary.BigEndian.PutUint16(r[8:10], 443)
				binary.BigEndian.PutUint16(r[10:12], 51234)
				binary.BigEndian.PutUint32(r[12:16], 200)
				binary.BigEndian.PutUint32(r[16:20], 90000)
				binary.BigEndian.PutUint32(r[20:24], fixtureV8FirstMs)
				binary.BigEndian.PutUint32(r[24:28], fixtureV8LastMs)
				binary.BigEndian.PutUint16(r[28:30], 4)
				binary.BigEndian.PutUint16(r[30:32], 3)
				r[32] = 0xB8
				r[33] = 6
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.Flows = 1
				w.DstAddr, w.SrcAddr, w.DstPort, w.SrcPort = dstPrefix, srcPrefix, 443, 51234
				w.OutputIf, w.InputIf, w.TOS, w.Protocol = 4, 3, 0xB8, 6
				w.TOSReported = true
				return w
			},
		},
		{
			name:        "9 tos AS",
			aggregation: 9,
			record: func() []byte {
				r := make([]byte, 32)
				putV8Common(r)
				binary.BigEndian.PutUint16(r[20:22], 64500)
				binary.BigEndian.PutUint16(r[22:24], 64501)
				binary.BigEndian.PutUint16(r[24:26], 3)
				binary.BigEndian.PutUint16(r[26:28], 4)
				r[28] = 0xB8
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAS, w.DstAS, w.InputIf, w.OutputIf, w.TOS = 64500, 64501, 3, 4, 0xB8
				w.TOSReported = true
				return w
			},
		},
		{
			name:        "10 tos protocol port",
			aggregation: 10,
			record: func() []byte {
				r := make([]byte, 32)
				putV8Common(r)
				r[20] = 17
				r[21] = 0xB8
				binary.BigEndian.PutUint16(r[24:26], 53000)
				binary.BigEndian.PutUint16(r[26:28], 53)
				binary.BigEndian.PutUint16(r[28:30], 3)
				binary.BigEndian.PutUint16(r[30:32], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.Protocol, w.TOS, w.SrcPort, w.DstPort = 17, 0xB8, 53000, 53
				w.TOSReported = true
				w.InputIf, w.OutputIf = 3, 4
				return w
			},
		},
		{
			name:        "11 tos source prefix",
			aggregation: 11,
			record: func() []byte {
				r := make([]byte, 32)
				putV8Common(r)
				copy(r[20:24], srcPrefix.AsSlice())
				r[24] = 16
				r[25] = 0xB8
				binary.BigEndian.PutUint16(r[26:28], 64500)
				binary.BigEndian.PutUint16(r[28:30], 3)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAddr, w.SrcMask, w.TOS, w.SrcAS, w.InputIf = srcPrefix, 16, 0xB8, 64500, 3
				w.TOSReported = true
				return w
			},
		},
		{
			name:        "12 tos destination prefix",
			aggregation: 12,
			record: func() []byte {
				r := make([]byte, 32)
				putV8Common(r)
				copy(r[20:24], dstPrefix.AsSlice())
				r[24] = 17
				r[25] = 0xB8
				binary.BigEndian.PutUint16(r[26:28], 64501)
				binary.BigEndian.PutUint16(r[28:30], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.DstAddr, w.DstMask, w.TOS, w.DstAS, w.OutputIf = dstPrefix, 17, 0xB8, 64501, 4
				w.TOSReported = true
				return w
			},
		},
		{
			name:        "13 tos prefix",
			aggregation: 13,
			record: func() []byte {
				r := make([]byte, 40)
				putV8Common(r)
				copy(r[20:24], srcPrefix.AsSlice())
				copy(r[24:28], dstPrefix.AsSlice())
				r[28] = 17
				r[29] = 16
				r[30] = 0xB8
				binary.BigEndian.PutUint16(r[32:34], 64500)
				binary.BigEndian.PutUint16(r[34:36], 64501)
				binary.BigEndian.PutUint16(r[36:38], 3)
				binary.BigEndian.PutUint16(r[38:40], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAddr, w.DstAddr, w.DstMask, w.SrcMask, w.TOS = srcPrefix, dstPrefix, 17, 16, 0xB8
				w.TOSReported = true
				w.SrcAS, w.DstAS, w.InputIf, w.OutputIf = 64500, 64501, 3, 4
				return w
			},
		},
		{
			name:        "14 prefix port",
			aggregation: 14,
			record: func() []byte {
				r := make([]byte, 40)
				putV8Common(r)
				copy(r[20:24], srcPrefix.AsSlice())
				copy(r[24:28], dstPrefix.AsSlice())
				r[28] = 17
				r[29] = 16
				r[30] = 0xB8
				r[31] = 6
				binary.BigEndian.PutUint16(r[32:34], 51234)
				binary.BigEndian.PutUint16(r[34:36], 443)
				binary.BigEndian.PutUint16(r[36:38], 3)
				binary.BigEndian.PutUint16(r[38:40], 4)
				return r
			},
			want: func() flow.Record {
				w := baseV8Want()
				w.SrcAddr, w.DstAddr, w.DstMask, w.SrcMask = srcPrefix, dstPrefix, 17, 16
				w.TOS, w.Protocol, w.SrcPort, w.DstPort = 0xB8, 6, 51234, 443
				w.TOSReported = true
				w.InputIf, w.OutputIf = 3, 4
				return w
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			payload := append(buildV8Header(tt.aggregation, 1), tt.record()...)

			records, decErr := decodeNetFlowV8(testExporter, payload, nil)
			if decErr != nil {
				t.Fatalf("decodeNetFlowV8() error = %v, want nil", decErr)
			}
			if len(records) != 1 {
				t.Fatalf("decodeNetFlowV8() returned %d records, want 1", len(records))
			}
			if got, want := records[0], tt.want(); got != want {
				t.Errorf("decodeNetFlowV8() record =\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}

func TestDecodeNetFlowV8_ReadsEveryClaimedRecord(t *testing.T) {
	t.Parallel()

	record := make([]byte, 28)
	putV8Common(record)

	payload := buildV8Header(1, 3)
	for range 3 {
		payload = append(payload, record...)
	}

	records, decErr := decodeNetFlowV8(testExporter, payload, nil)
	if decErr != nil {
		t.Fatalf("decodeNetFlowV8() error = %v, want nil", decErr)
	}
	if len(records) != 3 {
		t.Errorf("decodeNetFlowV8() returned %d records, want 3", len(records))
	}
}

func TestDecodeNetFlowV8_RejectsBrokenDatagrams(t *testing.T) {
	t.Parallel()

	record := make([]byte, 28)
	putV8Common(record)
	valid := append(buildV8Header(1, 1), record...)

	tests := []struct {
		name       string
		payload    []byte
		wantReason string
	}{
		{
			name:       "header cut short",
			payload:    valid[:20],
			wantReason: ReasonMalformed,
		},
		{
			name: "wrong aggregation export version",
			payload: func() []byte {
				p := append([]byte(nil), valid...)
				p[23] = 1
				return p
			}(),
			wantReason: ReasonMalformed,
		},
		{
			name:       "unknown aggregation method",
			payload:    append(buildV8Header(15, 1), record...),
			wantReason: ReasonUnsupportedAggregation,
		},
		{
			name:       "aggregation method zero",
			payload:    append(buildV8Header(0, 1), record...),
			wantReason: ReasonUnsupportedAggregation,
		},
		{
			name: "zero record count",
			payload: func() []byte {
				p := append([]byte(nil), valid...)
				binary.BigEndian.PutUint16(p[2:4], 0)
				return p
			}(),
			wantReason: ReasonMalformed,
		},
		{
			name: "payload shorter than the claimed records",
			payload: func() []byte {
				p := append([]byte(nil), valid...)
				binary.BigEndian.PutUint16(p[2:4], 2)
				return p
			}(),
			wantReason: ReasonMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			records, decErr := decodeNetFlowV8(testExporter, tt.payload, nil)
			if decErr == nil {
				t.Fatal("decodeNetFlowV8() error = nil, want a rejection")
			}
			if decErr.Reason() != tt.wantReason {
				t.Errorf("Reason() = %q, want %q", decErr.Reason(), tt.wantReason)
			}
			if len(records) != 0 {
				t.Errorf("decodeNetFlowV8() returned %d records alongside the error, want 0", len(records))
			}
		})
	}
}

func BenchmarkDecodeNetFlowV8(b *testing.B) {
	record := make([]byte, 28)
	putV8Common(record)
	payload := buildV8Header(1, 51)
	for range 51 {
		payload = append(payload, record...)
	}
	records := make([]flow.Record, 0, 51)

	b.ReportAllocs()
	for b.Loop() {
		var err *decodeError
		records, err = decodeNetFlowV8(testExporter, payload, records[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}
