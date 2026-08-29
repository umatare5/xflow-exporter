// This file holds the counters the read loops write and a scrape reads.

package receiver

import (
	"sync/atomic"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// ListenerStats carries one listener's counters. The read loop writes them
// lock-free and a scrape reads them through Snapshot.
type ListenerStats struct {
	Packets          atomic.Uint64
	Bytes            atomic.Uint64
	ReadErrors       atomic.Uint64
	DroppedQueueFull atomic.Uint64
	DroppedTruncated atomic.Uint64
}

// Stats indexes the per-listener counters. The map is built once at
// construction and never written again, so reads need no lock.
type Stats struct {
	listeners map[string]*ListenerStats
	order     []string
}

// newStats seeds one counter set per configured listener, so every series
// exists from the first scrape onward.
func newStats(cfg config.Receiver) *Stats {
	listeners := make(map[string]*ListenerStats, len(cfg.Addresses))
	order := make([]string, 0, len(cfg.Addresses))
	for _, address := range cfg.Addresses {
		listeners[address] = &ListenerStats{}
		order = append(order, address)
	}
	return &Stats{listeners: listeners, order: order}
}

// Listener returns the counter set of one configured listener.
func (s *Stats) Listener(address string) *ListenerStats {
	return s.listeners[address]
}

// ListenerSnapshot is one listener's counters at one instant.
type ListenerSnapshot struct {
	Listener         string
	Packets          uint64
	Bytes            uint64
	ReadErrors       uint64
	DroppedQueueFull uint64
	DroppedTruncated uint64
}

// Snapshot returns every listener's counters in configuration order.
func (s *Stats) Snapshot() []ListenerSnapshot {
	snapshots := make([]ListenerSnapshot, 0, len(s.order))
	for _, address := range s.order {
		ls := s.listeners[address]
		snapshots = append(snapshots, ListenerSnapshot{
			Listener:         address,
			Packets:          ls.Packets.Load(),
			Bytes:            ls.Bytes.Load(),
			ReadErrors:       ls.ReadErrors.Load(),
			DroppedQueueFull: ls.DroppedQueueFull.Load(),
			DroppedTruncated: ls.DroppedTruncated.Load(),
		})
	}
	return snapshots
}
