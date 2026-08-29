package aggregator

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// TestAggregator_EvictionLeavesTheOverflowAlone pins that an evicted entry's
// lifetime is not re-published on the other series. Prometheus counted those
// bytes as increments on the entry's own series while it lived; folding them
// again at eviction would make sum(rate()) over the family read twice what
// was ingested. The overflow bucket still only ever rises -- it just rises
// from ingest-time capacity folds alone.
func TestAggregator_EvictionLeavesTheOverflowAlone(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.EntryTTL = time.Minute
	a := New(cfg, Modules{Hosts: true})

	now := time.Unix(1_756_700_000, 0)
	a.now = func() time.Time { return now }

	r := testRecord()
	r.Bytes = 700
	a.Ingest([]flow.Record{r})

	_, before := a.Hosts()
	if before.Bytes != 0 {
		t.Fatalf("overflow = %+v before any eviction, want empty", before)
	}

	now = now.Add(2 * time.Minute)
	a.sweep()

	entries, after := a.Hosts()
	if len(entries) != 0 {
		t.Fatalf("entries = %d after the sweep, want 0", len(entries))
	}
	if after != (Totals{}) {
		t.Errorf("overflow = %+v after the eviction, want it untouched", after)
	}
}

// TestAggregator_OverflowNeverDecreases walks a churning table and pins that
// the overflow bucket only ever rises, which is what makes it publishable as
// a counter.
func TestAggregator_OverflowNeverDecreases(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.EntryTTL = time.Minute
	cfg.MaxEntries = 4
	a := New(cfg, Modules{Hosts: true})

	now := time.Unix(1_756_700_000, 0)
	a.now = func() time.Time { return now }

	var last Totals
	for round := range 10 {
		for i := range 6 {
			r := testRecord()
			r.SrcAddr = netip.AddrFrom4([4]byte{10, byte(round), 0, byte(i)})
			r.Bytes = 100
			a.Ingest([]flow.Record{r})
		}

		now = now.Add(2 * time.Minute)
		a.sweep()

		_, overflow := a.Hosts()
		if overflow.Bytes < last.Bytes || overflow.Packets < last.Packets || overflow.Flows < last.Flows {
			t.Fatalf("round %d: overflow fell from %+v to %+v", round, last, overflow)
		}
		last = overflow
	}

	if last.Bytes == 0 {
		t.Error("overflow never rose, the test exercised nothing")
	}
}

// TestTable_AddUnderSweepLosesNothing is the regression test for the lost
// update between add and sweep. The window was between reading the entry and
// accumulating into it, so the check drives both concurrently and compares
// the published totals against what was ingested.
func TestTable_AddUnderSweepLosesNothing(t *testing.T) {
	t.Parallel()

	const (
		workers = 4
		perAdd  = 100
		rounds  = 500
	)

	tbl := newTable[int](1024)

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range rounds {
				tbl.add(w, perAdd, 1, 1, int64(i))
			}
		}()
	}

	// Sweep continuously with a cutoff that keeps evicting, so the eviction
	// path and the add path interleave on the same keys throughout.
	stop := make(chan struct{})
	swept := make(chan struct{})
	var evicted Totals
	go func() {
		defer close(swept)
		for {
			select {
			case <-stop:
				return
			default:
				_, dropped := tbl.sweep(int64(rounds))
				evicted.Bytes += dropped.Bytes
				evicted.Packets += dropped.Packets
				evicted.Flows += dropped.Flows
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-swept

	entries, overflow := tbl.snapshot()
	total := overflow
	total.Bytes += evicted.Bytes
	total.Packets += evicted.Packets
	total.Flows += evicted.Flows
	for _, e := range entries {
		total.Bytes += e.Bytes
		total.Packets += e.Packets
		total.Flows += e.Flows
	}

	if want := uint64(workers * rounds * perAdd); total.Bytes != want {
		t.Errorf("bytes = %d across entries, overflow and evictions, want %d", total.Bytes, want)
	}
	if want := uint64(workers * rounds); total.Flows != want {
		t.Errorf("flows = %d, want %d ingested", total.Flows, want)
	}
}
