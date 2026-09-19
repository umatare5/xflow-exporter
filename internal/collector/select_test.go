package collector

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
)

// TestPublished_SelectsWhatAFullSortWouldPublish pins the selection against
// the order it replaces. A scrape orders only as far as the cut reaches, so
// the published set is what has to be identical -- not the tail, which the
// other series folds whatever its order.
//
// The shapes below are the ones a partition gets wrong: a table already in
// order, one in reverse, one of a single repeated value, and random ones at
// sizes either side of the cut.
func TestPublished_SelectsWhatAFullSortWouldPublish(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(n int) []aggregator.EntrySnapshot[int]
	}{
		{"random bytes", func(n int) []aggregator.EntrySnapshot[int] {
			return entriesFrom(n, func(i int) uint64 { return rand.Uint64N(1000) })
		}},
		{"already in order", func(n int) []aggregator.EntrySnapshot[int] {
			return entriesFrom(n, func(i int) uint64 { return uint64(n - i) })
		}},
		{"in reverse", func(n int) []aggregator.EntrySnapshot[int] {
			return entriesFrom(n, func(i int) uint64 { return uint64(i) })
		}},
		{"one value throughout", func(n int) []aggregator.EntrySnapshot[int] {
			return entriesFrom(n, func(i int) uint64 { return 7 })
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, n := range []int{0, 1, 2, 9, 10, 11, 64, 999} {
				for _, topK := range []int{0, 1, 10, 1000} {
					c := &FlowCollector{topK: topK}
					entries := tt.build(n)

					want := slices.Clone(entries)
					sortEntries(want)
					want = cutOf(c, want)

					got := published(c, slices.Clone(entries))
					if !slices.Equal(got, want) {
						t.Fatalf("published(n=%d, topK=%d) = %v, want %v", n, topK, got, want)
					}
				}
			}
		})
	}
}

// TestPublished_HonoursTheByteFloor pins that the floor still cuts inside the
// selected prefix, the two bounds being independent.
func TestPublished_HonoursTheByteFloor(t *testing.T) {
	t.Parallel()

	c := &FlowCollector{topK: 5, minBytes: 400}
	entries := entriesFrom(10, func(i int) uint64 { return uint64(10-i) * 50 })

	got := published(c, entries)
	if len(got) != 3 {
		t.Fatalf("published() kept %d entries, want the three at or above the floor", len(got))
	}
	for _, e := range got {
		if e.Bytes < c.minBytes {
			t.Errorf("published() kept an entry of %d bytes, below the floor of %d", e.Bytes, c.minBytes)
		}
	}
}

// entriesFrom builds a table whose keys and birth order are distinct, so the
// comparison is total and the expected set is unambiguous.
func entriesFrom(n int, bytes func(i int) uint64) []aggregator.EntrySnapshot[int] {
	entries := make([]aggregator.EntrySnapshot[int], n)
	for i := range entries {
		entries[i].Key = i
		entries[i].Born = uint64(i)
		entries[i].Bytes = bytes(i)
	}
	return entries
}
