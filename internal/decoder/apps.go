// Package decoder turns received datagrams into normalized flow records.
// This file holds the per-exporter application tables Cisco AVC announces
// through options, and the string interner every vendor string goes through.
package decoder

import (
	"bytes"
	"net/netip"
	"sync"
)

// appTables resolves an applicationId into the name and category the device
// itself announced. Tables are per exporter: every observation domain of one
// device shares one NBAR2 database.
type appTables struct {
	mu     sync.RWMutex
	tables map[netip.Addr]*appTable
}

// appTable is one device's announcements.
type appTable struct {
	mu         sync.RWMutex
	names      map[uint32]string
	categories map[uint32]string
}

// newAppTables creates an empty resolver.
func newAppTables() *appTables {
	return &appTables{tables: make(map[netip.Addr]*appTable)}
}

// table returns one exporter's table, creating it on first use.
func (a *appTables) table(exporter netip.Addr) *appTable {
	a.mu.RLock()
	t, ok := a.tables[exporter]
	a.mu.RUnlock()
	if ok {
		return t
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.tables[exporter]; ok {
		return t
	}
	t = &appTable{
		names:      make(map[uint32]string),
		categories: make(map[uint32]string),
	}
	a.tables[exporter] = t
	return t
}

// setName records one application's name as the device announced it.
func (a *appTables) setName(exporter netip.Addr, appID uint32, name []byte) {
	t := a.table(exporter)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.names[appID] = string(trimPadding(name))
}

// setCategory records one application's category.
func (a *appTables) setCategory(exporter netip.Addr, appID uint32, category []byte) {
	t := a.table(exporter)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.categories[appID] = string(trimPadding(category))
}

// resolve returns the name and category announced for one application, empty
// where the table has none: absence must stay absence.
func (a *appTables) resolve(exporter netip.Addr, appID uint32) (name, category string) {
	a.mu.RLock()
	t, ok := a.tables[exporter]
	a.mu.RUnlock()
	if !ok {
		return "", ""
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.names[appID], t.categories[appID]
}

// maxInternedStrings bounds the interner against a device exporting an
// unbounded set of vendor strings, whose values are wire data rather than a
// property of the fleet. Past the bound a value is copied per occurrence
// instead of being interned: the cost is an allocation on a path that is no
// longer the steady state, never a wrong or missing reading.
const maxInternedStrings = 65536

// interner deduplicates the strings vendors embed in every record, so one
// application name allocates once rather than per flow.
type interner struct {
	mu sync.RWMutex
	m  map[string]string
}

// newInterner creates an empty interner.
func newInterner() *interner {
	return &interner{m: make(map[string]string)}
}

// intern returns the canonical copy of value with export padding removed. The
// read path allocates nothing for a string already seen: the compiler elides
// the []byte-to-string conversion inside a map index.
func (i *interner) intern(value []byte) string {
	trimmed := trimPadding(value)
	if len(trimmed) == 0 {
		return ""
	}

	i.mu.RLock()
	s, ok := i.m[string(trimmed)]
	i.mu.RUnlock()
	if ok {
		return s
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	if s, ok := i.m[string(trimmed)]; ok {
		return s
	}
	if len(i.m) >= maxInternedStrings {
		return string(trimmed)
	}
	s = string(trimmed)
	i.m[s] = s
	return s
}

// trimPadding strips the trailing NULs and spaces fixed-width string exports
// pad with.
func trimPadding(value []byte) []byte {
	return bytes.TrimRight(value, "\x00 ")
}
