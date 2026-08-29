// This file holds the counters the workers write and a scrape reads.

package decoder

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// versionCount is how many flow.Version values exist, for the fixed-size
// per-version counter arrays below.
const versionCount = int(flow.VersionSFlowV5) + 1

// maxExporters bounds the devices this process holds counters for. UDP has no
// handshake, so the source address is whatever the sender wrote, and the first
// error path of Decode reaches this map before anything has been validated.
//
// Every other budget in this package bounds a wire field inside a device
// already admitted; this one bounds the fleet, so it sits above the largest
// fleet one collector plausibly serves rather than at the memory it costs. A
// campus or a provider edge is hundreds to low thousands of devices, and an
// sFlow host agent per node makes the largest case thousands more. It is the
// figure maxInternedStrings uses, the other table here that is filled from the
// wire and belongs to the process rather than to a device.
const maxExporters = 65536

// ExporterStats carries one exporting device's counters. The flow counts and
// the instants are written lock-free; an error counter takes errorsMu to reach
// its map. A scrape reads them all through Snapshot.
type ExporterStats struct {
	flows [versionCount]atomic.Uint64
	// errors is keyed by reason within version. Reasons are a closed set, so
	// the inner map is built once per version on first use, under errorsMu.
	errorsMu sync.Mutex
	errors   [versionCount]map[string]*atomic.Uint64
	// lastFlowUnixNano is when the last datagram decoded successfully, which
	// is the freshness signal a silent device is detected by.
	lastFlowUnixNano atomic.Int64
	// lastSeenUnixNano is when a datagram last named this device at all,
	// which the idle sweep reads. It is not lastFlowUnixNano: a device whose
	// every export is malformed is present, and its error counters are what
	// says so. Nor could the sweep use decode success as its test -- sixteen
	// bytes of well-formed IPFIX header decode, so that predicate is
	// forgeable by anyone who can send a datagram.
	lastSeenUnixNano atomic.Int64
}

// countFlows accounts one successfully decoded datagram. A nil receiver is a
// device the exporter budget refused, which holds no counters to add to.
func (e *ExporterStats) countFlows(version flow.Version, records int, at time.Time) {
	if e == nil {
		return
	}
	e.flows[version].Add(uint64(records)) //nolint:gosec // A record count is never negative.
	e.lastFlowUnixNano.Store(at.UnixNano())
}

// countError accounts one rejected flowset, sample or datagram. A nil
// receiver is a device the exporter budget refused.
func (e *ExporterStats) countError(version flow.Version, reason string) {
	if e == nil {
		return
	}
	e.counter(version, reason).Add(1)
}

// counter returns the error counter for one version and reason, creating it
// on first use.
func (e *ExporterStats) counter(version flow.Version, reason string) *atomic.Uint64 {
	e.errorsMu.Lock()
	defer e.errorsMu.Unlock()

	if e.errors[version] == nil {
		e.errors[version] = make(map[string]*atomic.Uint64)
	}
	counter, ok := e.errors[version][reason]
	if !ok {
		counter = &atomic.Uint64{}
		e.errors[version][reason] = counter
	}
	return counter
}

// Stats indexes the per-exporter counters. Exporters appear on their first
// datagram: a push protocol cannot know its senders in advance.
type Stats struct {
	mu        sync.RWMutex
	exporters map[netip.Addr]*ExporterStats

	// live mirrors len(exporters), written under the same lock. A datagram
	// from an address the budget refuses reads this instead of taking the
	// write lock that every worker and every scrape contend for; the count
	// under the lock stays the authority, so the bound holds either way.
	live atomic.Int64

	// refused counts the datagrams whose device the budget turned away, so
	// the devices left unaccounted are visible rather than silent. Decode
	// resolves each datagram's device once, which is what keeps this a
	// datagram count rather than a count of accounting calls.
	refused atomic.Uint64
}

// newStats creates empty decode statistics.
func newStats() *Stats {
	return &Stats{exporters: make(map[netip.Addr]*ExporterStats)}
}

// exporter returns the counter set of one device, creating it on first use
// and reporting nil once the process is at its exporter budget. The refusal
// is counted here, so Decode calls this once per datagram.
func (s *Stats) exporter(addr netip.Addr, at time.Time) *ExporterStats {
	now := at.UnixNano()

	s.mu.RLock()
	es, ok := s.exporters[addr]
	s.mu.RUnlock()
	if ok {
		es.lastSeenUnixNano.Store(now)
		return es
	}
	if s.live.Load() >= maxExporters {
		s.refused.Add(1)
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if es, ok := s.exporters[addr]; ok {
		es.lastSeenUnixNano.Store(now)
		return es
	}
	if len(s.exporters) >= maxExporters {
		s.refused.Add(1)
		return nil
	}

	es = &ExporterStats{}
	es.lastSeenUnixNano.Store(now)
	s.exporters[addr] = es
	s.live.Store(int64(len(s.exporters)))
	return es
}

// refusedCount reports how many datagrams the budget left unattributed.
func (s *Stats) refusedCount() uint64 {
	return s.refused.Load()
}

// sweepIdle drops the devices silent since before cutoff, but only once the
// budget is reached. Below it nothing is ever evicted: a device that has gone
// quiet is exactly what the freshness series exists to show, and a sweep that
// removed it would resolve the alarm by deleting the evidence.
func (s *Stats) sweepIdle(cutoff int64) int {
	if s.live.Load() < maxExporters {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	evicted := 0
	for addr, es := range s.exporters {
		if es.lastSeenUnixNano.Load() >= cutoff {
			continue
		}
		delete(s.exporters, addr)
		evicted++
	}
	s.live.Store(int64(len(s.exporters)))
	return evicted
}

// ErrorSnapshot is one error counter at one instant.
type ErrorSnapshot struct {
	Version flow.Version
	Reason  string
	Count   uint64
}

// FlowSnapshot is one per-version flow counter at one instant.
type FlowSnapshot struct {
	Version flow.Version
	Count   uint64
}

// ExporterSnapshot is one device's counters at one instant.
type ExporterSnapshot struct {
	Exporter netip.Addr
	Flows    []FlowSnapshot
	Errors   []ErrorSnapshot
	// LastFlowUnixNano is zero until a datagram decodes successfully.
	LastFlowUnixNano int64
}

// Snapshot returns every known exporter's counters. Only versions and reasons
// that have counted at least once appear: fabricating zero series for every
// version a device never spoke would be absence published as a reading.
func (s *Stats) Snapshot() []ExporterSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshots := make([]ExporterSnapshot, 0, len(s.exporters))
	for addr, es := range s.exporters {
		snapshots = append(snapshots, snapshotExporter(addr, es))
	}
	return snapshots
}

// snapshotExporter reads one device's counters.
func snapshotExporter(addr netip.Addr, es *ExporterStats) ExporterSnapshot {
	snap := ExporterSnapshot{
		Exporter:         addr,
		LastFlowUnixNano: es.lastFlowUnixNano.Load(),
	}

	for v := range versionCount {
		if count := es.flows[v].Load(); count > 0 {
			snap.Flows = append(snap.Flows, FlowSnapshot{Version: flow.Version(v), Count: count})
		}
	}

	es.errorsMu.Lock()
	defer es.errorsMu.Unlock()
	for v := range versionCount {
		for reason, counter := range es.errors[v] {
			snap.Errors = append(snap.Errors, ErrorSnapshot{
				Version: flow.Version(v),
				Reason:  reason,
				Count:   counter.Load(),
			})
		}
	}

	return snap
}
