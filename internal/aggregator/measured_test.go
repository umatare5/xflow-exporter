package aggregator

import (
	"testing"
)

// TestTable_KeepsASumMissingACountUnmeasured pins the latch the measured
// flags are. An entry one of whose records carried no count holds a sum short
// of the traffic it names, and every complete record after widens the gap
// rather than closing it, so the flag never clears.
//
// The two counters latch apart: a device reporting packets but no bytes
// leaves the packet sum publishable.
func TestTable_KeepsASumMissingACountUnmeasured(t *testing.T) {
	t.Parallel()

	whole := reading{bytes: 100, packets: 1, flows: 1, bytesMeasured: true, packetsMeasured: true}

	for name, tc := range map[string]struct {
		short       reading
		wantBytes   bool
		wantPackets bool
	}{
		"a record carrying no byte count": {
			short:       reading{packets: 1, flows: 1, packetsMeasured: true},
			wantPackets: true,
		},
		"a record carrying no packet count": {
			short:     reading{bytes: 100, flows: 1, bytesMeasured: true},
			wantBytes: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			const wholeRecords = 10

			table := newTable[string](8)
			table.add("one", tc.short, 1)
			for range wholeRecords {
				table.add("one", whole, 1)
			}

			entries, _ := table.snapshot()
			if len(entries) != 1 {
				t.Fatalf("snapshot() = %d entries, want the one the key names", len(entries))
			}

			got := entries[0].Totals
			if got.BytesMeasured != tc.wantBytes || got.PacketsMeasured != tc.wantPackets {
				t.Errorf("measured = bytes %v packets %v, want %v and %v",
					got.BytesMeasured, got.PacketsMeasured, tc.wantBytes, tc.wantPackets)
			}
			if got.Flows != wholeRecords+1 {
				t.Errorf("Flows = %d, want every record counted", got.Flows)
			}
		})
	}
}
