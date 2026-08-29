// Package aggregator accumulates flow records into bounded in-memory tables
// the collectors read at scrape time.
// This file holds the generic table every aggregation shares.
package aggregator

import (
	"sync"
	"sync/atomic"
)

// Totals is one entry's accumulated counters.
type Totals struct {
	Bytes   uint64
	Packets uint64
	Flows   uint64
}

// entry carries one key's counters. The counters are atomic so the ingest
// path updates a present entry under the table's read lock alone.
type entry struct {
	bytes    atomic.Uint64
	packets  atomic.Uint64
	flows    atomic.Uint64
	lastSeen atomic.Int64
}

// add accumulates one record into the entry.
func (e *entry) add(bytes, packets, flows uint64, now int64) {
	e.bytes.Add(bytes)
	e.packets.Add(packets)
	e.flows.Add(flows)
	e.lastSeen.Store(now)
}

// totals reads the entry.
func (e *entry) totals() Totals {
	return Totals{
		Bytes:   e.bytes.Load(),
		Packets: e.packets.Load(),
		Flows:   e.flows.Load(),
	}
}

// table is one aggregation's key-to-entry map with its bounds. A record whose
// key is new while the table is full folds into the overflow entry, whose
// series carries the label value "other".
type table[K comparable] struct {
	mu      sync.RWMutex
	entries map[K]*entry

	maxEntries int

	// overflow accumulates what the bound rejected and what eviction took
	// away, so the family's other series stays monotonic: a total that has
	// once been counted is never withdrawn from it. Its lastSeen never
	// evicts it, the bucket being part of the table rather than an entry.
	overflow entry

	idleEvictions atomic.Uint64
	capacityFolds atomic.Uint64
}

// newTable creates an empty table with the given entry bound.
func newTable[K comparable](maxEntries int) *table[K] {
	return &table[K]{
		entries:    make(map[K]*entry),
		maxEntries: maxEntries,
	}
}

// add accumulates one record under key, folding into the overflow bucket
// when the key is new and the table is at its bound.
//
// The accumulation happens under the lock rather than after releasing it: a
// sweep taking the write lock in that window would evict the entry, and the
// record would then land on a map nobody reads any more.
func (t *table[K]) add(key K, bytes, packets, flows uint64, now int64) {
	t.mu.RLock()
	e, ok := t.entries[key]
	if ok {
		e.add(bytes, packets, flows, now)
	}
	t.mu.RUnlock()

	if ok {
		return
	}

	if !t.insert(key, bytes, packets, flows, now) {
		t.capacityFolds.Add(1)
		t.overflow.add(bytes, packets, flows, now)
	}
}

// insert creates the entry for key and applies the first record to it under
// the write lock, reporting false at the bound. Seeding the entry and
// accumulating into it are one step so a concurrent sweep cannot evict it
// between the two, which would lose the record that created it.
func (t *table[K]) insert(key K, bytes, packets, flows uint64, now int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.entries[key]; ok {
		e.add(bytes, packets, flows, now)
		return true
	}
	if len(t.entries) >= t.maxEntries {
		return false
	}

	e := &entry{}
	e.add(bytes, packets, flows, now)
	t.entries[key] = e
	return true
}

// sweep drops every entry idle since before cutoff and reports how many.
// Their own series disappear with them, which is the push-model spelling of
// absence: a flow nobody has seen for the TTL is not a zero, it is gone.
//
// The totals they carried move into the overflow bucket rather than vanishing.
// The other series is a counter, so withdrawing a total it has already
// published would read as a counter reset and give rate() a false spike.
func (t *table[K]) sweep(cutoff int64) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	evicted := 0
	for key, e := range t.entries {
		if e.lastSeen.Load() >= cutoff {
			continue
		}

		totals := e.totals()
		t.overflow.add(totals.Bytes, totals.Packets, totals.Flows, cutoff)
		delete(t.entries, key)
		evicted++
	}

	t.idleEvictions.Add(uint64(evicted)) //nolint:gosec // A map size is never negative.
	return evicted
}

// EntrySnapshot is one entry at one instant.
type EntrySnapshot[K comparable] struct {
	Key K
	Totals
}

// snapshot reads every entry and the overflow bucket.
func (t *table[K]) snapshot() ([]EntrySnapshot[K], Totals) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entries := make([]EntrySnapshot[K], 0, len(t.entries))
	for key, e := range t.entries {
		entries = append(entries, EntrySnapshot[K]{Key: key, Totals: e.totals()})
	}
	return entries, t.overflow.totals()
}

// size reports the current entry count.
func (t *table[K]) size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}
