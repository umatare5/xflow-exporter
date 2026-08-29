// Package decoder turns received datagrams into normalized flow records.
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

// ExporterStats carries one exporting device's counters. Workers write them
// lock-free; a scrape reads them through Snapshot.
type ExporterStats struct {
	flows [versionCount]atomic.Uint64
	// errors is keyed by reason within version. Reasons are a closed set, so
	// the inner map is built once per version on first use, under the same
	// lock as the exporter map.
	errorsMu sync.Mutex
	errors   [versionCount]map[string]*atomic.Uint64
	// lastFlowUnixNano is when the last datagram decoded successfully, which
	// is the freshness signal a silent device is detected by.
	lastFlowUnixNano atomic.Int64
}

// countFlows accounts one successfully decoded datagram.
func (e *ExporterStats) countFlows(version flow.Version, records int, at time.Time) {
	e.flows[version].Add(uint64(records)) //nolint:gosec // A record count is never negative.
	e.lastFlowUnixNano.Store(at.UnixNano())
}

// countError accounts one rejected datagram.
func (e *ExporterStats) countError(version flow.Version, reason string) {
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
}

// newStats creates empty decode statistics.
func newStats() *Stats {
	return &Stats{exporters: make(map[netip.Addr]*ExporterStats)}
}

// exporter returns the counter set of one device, creating it on first use.
func (s *Stats) exporter(addr netip.Addr) *ExporterStats {
	s.mu.RLock()
	es, ok := s.exporters[addr]
	s.mu.RUnlock()
	if ok {
		return es
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if es, ok := s.exporters[addr]; ok {
		return es
	}
	es = &ExporterStats{}
	s.exporters[addr] = es
	return es
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
