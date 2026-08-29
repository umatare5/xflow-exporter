// Package enrich fills flow record dimensions the exporting device did not
// carry, from sources local to this exporter.
//
// An enricher never overwrites a reading the device made. The device saw the
// packet and this exporter did not, so what it exported is the authority, and
// enrichment fills absence alone. That rule is what keeps an enriched series
// comparable with an unenriched one.
package enrich

import (
	"log/slog"
	"sync/atomic"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// Outcomes published in the result label of the lookup counter.
const (
	// ResultFilled marks a lookup that supplied a dimension.
	ResultFilled = "filled"
	// ResultUnknown marks a lookup whose source knew nothing, which leaves
	// the dimension absent rather than guessed.
	ResultUnknown = "unknown"
	// ResultSkipped marks a record that needed nothing, the device having
	// carried the dimension already.
	ResultSkipped = "skipped"
)

// Enricher fills what one source knows about a record.
type Enricher interface {
	// Enrich fills the dimensions this source can supply and leaves every
	// other field untouched.
	Enrich(r *flow.Record)
	// Name is the enricher's value in the enricher label.
	Name() string
	// Snapshot reports the lookup outcomes since process start.
	Snapshot() Snapshot
}

// Snapshot is one enricher's counters at one instant.
type Snapshot struct {
	Enricher string
	Filled   uint64
	Unknown  uint64
	Skipped  uint64
}

// counters is the outcome accounting every enricher embeds.
type counters struct {
	filled  atomic.Uint64
	unknown atomic.Uint64
	skipped atomic.Uint64
}

// snapshot reads the counters under one name.
func (c *counters) snapshot(name string) Snapshot {
	return Snapshot{
		Enricher: name,
		Filled:   c.filled.Load(),
		Unknown:  c.unknown.Load(),
		Skipped:  c.skipped.Load(),
	}
}

// Snapshotter is what the metrics collector reads. The chain satisfies it.
type Snapshotter interface {
	Snapshot() []Snapshot
}

// Chain applies its enrichers in order to every record of a batch. An empty
// chain is a no-op, so the ingest path needs no nil check.
type Chain struct {
	enrichers []Enricher
}

// NewChain creates a chain over the enabled enrichers.
func NewChain(enrichers ...Enricher) *Chain {
	return &Chain{enrichers: enrichers}
}

// Enabled reports whether the chain would do anything.
func (c *Chain) Enabled() bool {
	return c != nil && len(c.enrichers) > 0
}

// Enrich applies every enricher to every record.
func (c *Chain) Enrich(records []flow.Record) {
	if !c.Enabled() {
		return
	}

	for i := range records {
		record := &records[i]
		for _, e := range c.enrichers {
			e.Enrich(record)
		}
	}
}

// Snapshot reports every enricher's counters.
func (c *Chain) Snapshot() []Snapshot {
	if c == nil {
		return nil
	}

	snapshots := make([]Snapshot, 0, len(c.enrichers))
	for _, e := range c.enrichers {
		snapshots = append(snapshots, e.Snapshot())
	}
	return snapshots
}

// Close releases whatever the enrichers hold open.
func (c *Chain) Close() {
	if c == nil {
		return
	}

	for _, e := range c.enrichers {
		closer, ok := e.(interface{ Close() error })
		if !ok {
			continue
		}
		if err := closer.Close(); err != nil {
			slog.Debug("Failed to close an enrichment source", "enricher", e.Name(), "error", err)
		}
	}
}
