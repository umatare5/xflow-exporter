package decoder

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// spoofedAddr is a distinct address per index, which is what a sender writes
// into a UDP header at no cost.
func spoofedAddr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// TestStats_ExportersAreBounded is the regression test for a map that grew
// with the sender's imagination. UDP has no handshake, so the source address
// is whatever the sender wrote, and Decode reaches these counters on its first
// error path -- before anything has been validated. Nothing swept them, so one
// burst of spoofed addresses was held for the life of the process.
func TestStats_ExportersAreBounded(t *testing.T) {
	t.Parallel()

	s := newStats()
	now := time.Now()
	for i := range maxExporters + 1000 {
		s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, now)
	}

	if got := len(s.Snapshot()); got != maxExporters {
		t.Errorf("held %d devices, want the budget of %d", got, maxExporters)
	}
	if got := s.refusedCount(); got != 1000 {
		t.Errorf("refused = %d, want the 1000 datagrams past the budget", got)
	}
}

// TestStats_RefusedExporterPublishesNothing pins the absence half: a device
// the budget turned away carries no counters at all rather than zeroed ones.
func TestStats_RefusedExporterPublishesNothing(t *testing.T) {
	t.Parallel()

	s := newStats()
	now := time.Now()
	for i := range maxExporters {
		s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, now)
	}

	beyond := netip.MustParseAddr("203.0.113.9")
	s.countFlows(beyond, flow.VersionNetFlowV9, 5, now)
	s.countError(beyond, flow.VersionNetFlowV9, ReasonMalformed, now)

	for _, snap := range s.Snapshot() {
		if snap.Exporter == beyond {
			t.Fatalf("a refused device published %+v, want no series of any kind", snap)
		}
	}
}

// TestStats_SweepOnlyRunsUnderPressure pins what separates this sweep from the
// template store's. A device that has gone quiet is exactly what the freshness
// series exists to show, so below the budget an hour of silence must evict
// nothing: a sweep that ran unconditionally would resolve the silence alert by
// deleting its evidence.
func TestStats_SweepOnlyRunsUnderPressure(t *testing.T) {
	t.Parallel()

	s := newStats()
	long := time.Now().Add(-time.Hour)
	for i := range 100 {
		s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, long)
	}

	if evicted := s.sweepIdle(time.Now().UnixNano()); evicted != 0 {
		t.Errorf("swept %d devices below the budget, want none", evicted)
	}
	if got := len(s.Snapshot()); got != 100 {
		t.Errorf("held %d devices, want all 100 kept", got)
	}
}

// TestStats_SweepAtTheBudgetReclaims covers the other side: once the budget is
// reached the burst that filled it is reclaimed, so a table full of addresses
// nobody has used since is not a permanent state.
func TestStats_SweepAtTheBudgetReclaims(t *testing.T) {
	t.Parallel()

	s := newStats()
	long := time.Now().Add(-time.Hour)
	for i := range maxExporters {
		s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, long)
	}

	if evicted := s.sweepIdle(time.Now().UnixNano()); evicted != maxExporters {
		t.Errorf("swept %d devices, want the whole idle budget of %d", evicted, maxExporters)
	}

	// The slot is available again, which is what the sweep is for.
	fresh := netip.MustParseAddr("203.0.113.9")
	s.countFlows(fresh, flow.VersionNetFlowV9, 1, time.Now())
	if got := len(s.Snapshot()); got != 1 {
		t.Errorf("held %d devices after the sweep, want the one that arrived", got)
	}
}

// TestStats_SweepReadsTheLastDatagramNotTheLastDecode pins the qualification.
// Sixteen bytes of well-formed IPFIX header decode successfully, so "has
// decoded" is forgeable by anyone who can send a datagram and cannot qualify
// admission; and a device whose every export is malformed is present, its
// error counters being what says so.
func TestStats_SweepReadsTheLastDatagramNotTheLastDecode(t *testing.T) {
	t.Parallel()

	s := newStats()
	long := time.Now().Add(-time.Hour)
	for i := range maxExporters - 1 {
		s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, long)
	}

	// Erroring now, never decoded: seen, and must survive the sweep.
	erroring := netip.MustParseAddr("203.0.113.9")
	s.countError(erroring, flow.VersionNetFlowV9, ReasonMalformed, time.Now())

	s.sweepIdle(time.Now().Add(-time.Minute).UnixNano())

	var kept bool
	for _, snap := range s.Snapshot() {
		if snap.Exporter == erroring {
			kept = true
			if snap.LastFlowUnixNano != 0 {
				t.Errorf("LastFlowUnixNano = %d, want zero: it never decoded", snap.LastFlowUnixNano)
			}
		}
	}
	if !kept {
		t.Error("a device that erred a moment ago was swept, want it kept on its last datagram")
	}
}

// TestStats_BoundHoldsUnderConcurrentWorkers covers the admission decision
// read outside the write lock. The count under the lock stays the authority,
// so the budget is exact however many workers race for the last slots.
func TestStats_BoundHoldsUnderConcurrentWorkers(t *testing.T) {
	t.Parallel()

	s := newStats()
	now := time.Now()
	for i := range maxExporters - 1 {
		s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, now)
	}

	// Released together, so every worker reads the budget before any of them
	// has taken the last slot. Without the barrier the first insert closes the
	// gate and the rest never race for it.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.countError(spoofedAddr(maxExporters+i), flow.VersionUnknown, ReasonUnsupportedVersion, now)
		}()
	}
	close(start)
	wg.Wait()

	if got := len(s.Snapshot()); got > maxExporters {
		t.Errorf("held %d devices, want no more than the budget of %d", got, maxExporters)
	}
}

// TestDecoder_SweepExportersUsesTheTemplateTTL pins the wiring: the sweep the
// lifecycle loop already runs for observation domains carries this one too,
// on the same cutoff, rather than growing a second cadence.
func TestDecoder_SweepExportersUsesTheTemplateTTL(t *testing.T) {
	t.Parallel()

	d := New(config.Parser{
		MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
		TemplateTTL:          config.DefaultParserTemplateTTL,
	})
	base := time.Now()
	d.now = func() time.Time { return base }

	long := base.Add(-2 * config.DefaultParserTemplateTTL)
	for i := range maxExporters {
		d.stats.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, long)
	}

	if evicted := d.SweepExporters(); evicted != maxExporters {
		t.Errorf("SweepExporters() = %d, want the whole budget past the template TTL", evicted)
	}
	if got := d.ExportersRefused(); got != 0 {
		t.Errorf("ExportersRefused() = %d, want none: the budget was reached, not exceeded", got)
	}
}

// TestStats_BothBudgetGatesRefuse drives each gate on its own. The budget is
// read once outside the write lock and once inside it, and only the inner read
// is authoritative: a race can carry a worker past the outer one, and workers
// that never race must not queue on a lock they will be turned away by. Neither
// gate is reachable from the other's side, so each is planted rather than
// raced -- a race here measures the scheduler, not the code.
func TestStats_BothBudgetGatesRefuse(t *testing.T) {
	t.Parallel()

	t.Run("outside the lock, from the mirrored count", func(t *testing.T) {
		t.Parallel()

		s := newStats()
		s.live.Store(maxExporters)

		if es := s.exporter(netip.MustParseAddr("203.0.113.9"), time.Now()); es != nil {
			t.Error("exporter() admitted a device with the budget already reached")
		}
		if got := len(s.Snapshot()); got != 0 {
			t.Errorf("held %d devices, want none: nothing was admitted", got)
		}
		if got := s.refusedCount(); got != 1 {
			t.Errorf("refused = %d, want 1", got)
		}
	})

	t.Run("inside the lock, from the map itself", func(t *testing.T) {
		t.Parallel()

		s := newStats()
		now := time.Now()
		for i := range maxExporters {
			s.countError(spoofedAddr(i), flow.VersionUnknown, ReasonUnsupportedVersion, now)
		}
		// The mirrored count lies low, as a worker that read it before the
		// last slot went sees it. Only the count under the lock can refuse.
		s.live.Store(0)

		if es := s.exporter(netip.MustParseAddr("203.0.113.9"), now); es != nil {
			t.Error("exporter() admitted a device past a full map")
		}
		if got := len(s.Snapshot()); got != maxExporters {
			t.Errorf("held %d devices, want the budget of %d", got, maxExporters)
		}
	})
}
