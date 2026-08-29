// Package decoder turns received datagrams into normalized flow records.
// This file holds the per-exporter application tables Cisco AVC announces
// through options, and the string interner every vendor string goes through.
package decoder

import (
	"bytes"
	"net/netip"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// appTables resolves an applicationId into the name and category the device
// itself announced. Tables are per exporter: every observation domain of one
// device shares one NBAR2 database.
type appTables struct {
	// intern validates and deduplicates the announced strings. An options
	// template repeats one device's whole NBAR2 database on every refresh,
	// so the names are the same strings the records carry.
	intern *interner

	// refused counts the announcements the per-exporter budget turned away,
	// so the applications left unnamed are visible rather than silent.
	refused atomic.Uint64

	mu     sync.RWMutex
	tables map[netip.Addr]*appTable
}

// maxAppsPerExporter bounds one device's announced application table. The
// applicationId is a wire field rather than a property of the fleet, so a
// device with a broken numbering scheme, or one under an attacker's control,
// would otherwise mint entries without end from a single permitted source
// address, and nothing ever expires them. Cisco's NBAR2 protocol pack, the
// database this table carries, names on the order of 1500 applications, so
// the bound is an order of magnitude above what a real device announces.
const maxAppsPerExporter = 16384

// appTable is one device's announcements.
type appTable struct {
	mu         sync.RWMutex
	names      map[uint32]string
	categories map[uint32]string
}

// newAppTables creates an empty resolver.
func newAppTables(intern *interner) *appTables {
	return &appTables{intern: intern, tables: make(map[netip.Addr]*appTable)}
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
	value := a.intern.intern(name)
	if value == "" {
		return
	}

	t := a.table(exporter)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !admits(t.names, appID) {
		a.refused.Add(1)
		return
	}
	t.names[appID] = value
}

// setCategory records one application's category.
func (a *appTables) setCategory(exporter netip.Addr, appID uint32, category []byte) {
	value := a.intern.intern(category)
	if value == "" {
		return
	}

	t := a.table(exporter)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !admits(t.categories, appID) {
		a.refused.Add(1)
		return
	}
	t.categories[appID] = value
}

// admits reports whether one announcement fits the budget. An application
// already in the table always does, so a device at the bound keeps refreshing
// what it established.
func admits(m map[uint32]string, appID uint32) bool {
	if _, ok := m[appID]; ok {
		return true
	}
	return len(m) < maxAppsPerExporter
}

// refusedCount reports how many announcements the budget turned away.
func (a *appTables) refusedCount() uint64 {
	return a.refused.Load()
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

// maxVendorStringLength bounds one vendor string. The bound above counts
// strings rather than their bytes, so a device exporting names as wide as its
// datagram fills the interner with datagrams instead of names: 65536 of them
// at the default receive size is 597 MiB, held for the life of the process.
// An NBAR2 name and the category beside it are tens of bytes.
const maxVendorStringLength = 255

// interner deduplicates the strings vendors embed in every record, so one
// application name allocates once rather than per flow.
type interner struct {
	// refused counts the strings turned away as unrepresentable, so a
	// record reading as its application number rather than its name is
	// visible instead of silent.
	refused atomic.Uint64

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
	if len(trimmed) > maxVendorStringLength {
		i.refused.Add(1)
		return ""
	}

	// A vendor string arrives from the wire at whatever width the export
	// field was, so a name cut through a multi-byte rune is ordinary rather
	// than hostile, and Prometheus cannot hold it as a label value. Refusing
	// it here keeps it off the label path entirely, rather than leaving the
	// collector to drop the entry it would have named. Refusing leaves the
	// name unset,
	// which the layers above fall back from: to the numbered applicationId
	// where the record carries one, to the port name where the services
	// enricher is on, and to no application series at all where neither
	// knows -- never to a guessed or partial name.
	if !utf8.Valid(trimmed) {
		i.refused.Add(1)
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

// refusedCount reports how many vendor strings were turned away.
func (i *interner) refusedCount() uint64 {
	return i.refused.Load()
}

// trimPadding strips the trailing NULs and spaces fixed-width string exports
// pad with.
func trimPadding(value []byte) []byte {
	return bytes.TrimRight(value, "\x00 ")
}
