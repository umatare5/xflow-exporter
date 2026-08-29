// Package remotewrite ships the exporter's own registry to a remote endpoint.
// This file holds the counters the writer keeps and a scrape reads.
package remotewrite

import "sync/atomic"

// Stats reports the outcome of the remote writes.
type Stats struct {
	sends               atomic.Uint64
	failures            atomic.Uint64
	samples             atomic.Uint64
	lastSuccessUnixNano atomic.Int64
}

// Snapshot is the statistics at one instant.
type Snapshot struct {
	Sends    uint64
	Failures uint64
	Samples  uint64
	// LastSuccessUnixNano is zero until one write succeeds.
	LastSuccessUnixNano int64
}

// Snapshot reads the counters.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		Sends:               s.sends.Load(),
		Failures:            s.failures.Load(),
		Samples:             s.samples.Load(),
		LastSuccessUnixNano: s.lastSuccessUnixNano.Load(),
	}
}
