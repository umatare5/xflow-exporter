// Package remotewrite ships the exporter's own registry to a remote endpoint,
// for the deployments a Prometheus scrape cannot reach.
// This file builds the symbol table Remote Write 2.0 encodes labels through.
package remotewrite

import (
	writev2 "github.com/prometheus/client_golang/exp/api/remote/genproto/v2"
)

// symbolTable interns the strings of one request. Remote Write 2.0 carries
// labels as indices into a per-request array rather than as strings, which is
// what keeps a batch of series sharing a metric name from repeating it.
type symbolTable struct {
	symbols []string
	index   map[string]uint32
}

// newSymbolTable creates a table seeded with the empty string, which the
// specification requires at index zero.
func newSymbolTable() *symbolTable {
	return &symbolTable{
		symbols: []string{""},
		index:   map[string]uint32{"": 0},
	}
}

// intern returns the index of one string, adding it on first use.
func (t *symbolTable) intern(value string) uint32 {
	if ref, ok := t.index[value]; ok {
		return ref
	}

	ref := uint32(len(t.symbols)) //nolint:gosec // A request holds far fewer symbols than a uint32 counts.
	t.symbols = append(t.symbols, value)
	t.index[value] = ref
	return ref
}

// refsPerPair is how many references one label contributes: its name and its
// value, both as indices into the symbol table.
const refsPerPair = 2

// internPairs returns the flat name-value reference list one series carries.
// The specification requires the pairs sorted by label name, which the caller
// guarantees.
func (t *symbolTable) internPairs(pairs []labelPair) []uint32 {
	refs := make([]uint32, 0, len(pairs)*refsPerPair)
	for _, pair := range pairs {
		refs = append(refs, t.intern(pair.name), t.intern(pair.value))
	}
	return refs
}

// reset empties the table for the next request.
func (t *symbolTable) reset() {
	t.symbols = t.symbols[:1]
	clear(t.index)
	t.index[""] = 0
}

// labelPair is one label of a series.
type labelPair struct {
	name  string
	value string
}

// request assembles the write request from the interned series.
func (t *symbolTable) request(series []*writev2.TimeSeries) *writev2.Request {
	return &writev2.Request{
		Symbols:    t.symbols,
		Timeseries: series,
	}
}
