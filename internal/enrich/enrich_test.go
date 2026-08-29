package enrich

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// countingReloader observes how many rebuilds run at once.
type countingReloader struct {
	inFlight atomic.Int32
	peak     atomic.Int32
	runs     atomic.Int32
	order    chan int32
}

func (r *countingReloader) Enrich(*flow.Record) {}
func (r *countingReloader) Name() string        { return "counting" }
func (r *countingReloader) Snapshot() Snapshot  { return Snapshot{Enricher: r.Name()} }

func (r *countingReloader) Reload() error {
	n := r.inFlight.Add(1)
	for {
		peak := r.peak.Load()
		if n <= peak || r.peak.CompareAndSwap(peak, n) {
			break
		}
	}

	// Long enough that unserialized callers would overlap.
	time.Sleep(2 * time.Millisecond)

	seq := r.runs.Add(1)
	r.order <- seq
	r.inFlight.Add(-1)
	return nil
}

// TestChain_ReloadsOneAtATime pins the property both reload defects rest on.
// Without it every concurrent caller builds a whole set of its own before any
// of them publishes -- the peak grows with the callers rather than the data --
// and the set left in force is the build that finished last rather than the
// one that read the newest file. Both triggers reach the chain, so the guard
// belongs here rather than in one enricher.
func TestChain_ReloadsOneAtATime(t *testing.T) {
	t.Parallel()

	const callers = 16

	r := &countingReloader{order: make(chan int32, callers)}
	chain := NewChain(r)

	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			if err := chain.Reload(); err != nil {
				t.Errorf("Reload() error = %v, want nil", err)
			}
		}()
	}
	wg.Wait()
	close(r.order)

	if got := r.peak.Load(); got != 1 {
		t.Errorf("peak concurrent reloads = %d, want 1", got)
	}
	if got := r.runs.Load(); got != callers {
		t.Errorf("reloads run = %d, want every caller served", got)
	}

	// Each completion is the last one at the moment it publishes, so the
	// set in force is always the newest read rather than the slowest build.
	want := int32(0)
	for seq := range r.order {
		want++
		if seq != want {
			t.Errorf("completion order = %d, want %d: builds overlapped", seq, want)
		}
	}
}

// failingReloader fails every rebuild.
type failingReloader struct{ name string }

func (r *failingReloader) Enrich(*flow.Record) {}
func (r *failingReloader) Name() string        { return r.name }
func (r *failingReloader) Snapshot() Snapshot  { return Snapshot{Enricher: r.name} }
func (r *failingReloader) Reload() error       { return errors.New("the file could not be read") }

// TestChain_ReloadAttemptsEverySource pins that one source that cannot be
// re-read does not hold back the ones listed after it. The sources are
// separate files refreshed by separate steps of one cron job, so a truncated
// database must not cost the threat list its refresh.
func TestChain_ReloadAttemptsEverySource(t *testing.T) {
	t.Parallel()

	after := &countingReloader{order: make(chan int32, 1)}
	chain := NewChain(&failingReloader{name: "first"}, after)

	err := chain.Reload()
	if err == nil {
		t.Fatal("Reload() error = nil, want the failure reported")
	}
	if !strings.Contains(err.Error(), "reloading first") {
		t.Errorf("Reload() error = %v, want it to name the source", err)
	}
	if got := after.runs.Load(); got != 1 {
		t.Errorf("the source after the failure ran %d times, want 1", got)
	}
}
