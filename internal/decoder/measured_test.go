package decoder

import (
	"testing"
)

const measuredTemplateID = 830

// TestCounters_ReportWhatTheTemplateCarried pins the two flags the counts
// cannot carry themselves. A template keeping its counters in elements this
// decoder does not read leaves both at zero, and that zero is a template it
// cannot read rather than a flow that moved nothing.
func TestCounters_ReportWhatTheTemplateCarried(t *testing.T) {
	t.Parallel()

	const odid = 920

	tests := []struct {
		name        string
		fields      [][2]uint16
		record      []byte
		wantBytes   bool
		wantPackets bool
	}{
		{
			name:   "both counters",
			fields: [][2]uint16{{fieldInBytes, 4}, {fieldInPackets, 4}},
			record: be32(be32(nil, 1500), 10), wantBytes: true, wantPackets: true,
		},
		{
			name:   "bytes alone",
			fields: [][2]uint16{{fieldInBytes, 4}},
			record: be32(nil, 1500), wantBytes: true,
		},
		{
			name:   "packets alone",
			fields: [][2]uint16{{fieldInPackets, 4}},
			record: be32(nil, 10), wantPackets: true,
		},
		{
			// The counters ride IE 85 and IE 86 on such a device, which are
			// totals this exporter does not add to a delta.
			name:   "counters this decoder does not read",
			fields: [][2]uint16{{fieldIPv4SrcAddr, 4}},
			record: []byte{192, 0, 2, 10},
		},
		{
			// An egress-only template carries the OUT_ pair alone, which
			// wins where the IN_ pair is absent rather than reading as zero.
			name:   "the egress counters",
			fields: [][2]uint16{{fieldOutBytes, 4}, {fieldOutPackets, 4}},
			record: be32(be32(nil, 1500), 10), wantBytes: true, wantPackets: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decodeSampling(t, d, v9Packet(1, odid,
				flowSet(templateFlowSetID, templateSpec(measuredTemplateID, tc.fields...))))
			records := decodeSampling(t, d, v9Packet(2, odid,
				flowSet(measuredTemplateID, tc.record)))

			if len(records) != 1 {
				t.Fatalf("Decode() returned %d records, want 1", len(records))
			}
			if got := records[0].BytesReported; got != tc.wantBytes {
				t.Errorf("BytesReported = %t, want %t", got, tc.wantBytes)
			}
			if got := records[0].PacketsReported; got != tc.wantPackets {
				t.Errorf("PacketsReported = %t, want %t", got, tc.wantPackets)
			}
		})
	}
}
