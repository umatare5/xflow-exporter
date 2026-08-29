// Package enrich fills flow record dimensions the exporting device did not
// carry, from sources local to this exporter.
// This file reads MaxMind-format databases held on local disk.
package enrich

import (
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// mmdbSource is the database both mmdb-backed enrichers hold, and the swap
// that re-reads it.
//
// The reader is replaced wholesale on reload rather than reopened in place,
// so a lookup never consults a half-open database and never takes a lock --
// the same shape the threat list uses for the same reason.
type mmdbSource struct {
	// kind names the database in the errors an operator reads.
	kind string
	path string
	db   atomic.Pointer[maxminddb.Reader]
}

// reload opens the file again and publishes the reader it produced. A file
// that cannot be opened leaves the previous reader serving, so a truncated
// download never turns every lookup into a miss.
//
// The reader that was in force is dropped, not closed. maxminddb.Close
// unmaps the file, and the library's own contract forbids a Close concurrent
// with a lookup: a lookup on the decode path would read unmapped memory,
// which faults rather than erroring, and nothing on that path recovers.
// Dropping the last reference is the release instead. maxminddb.Open
// registers a runtime cleanup that unmaps once the reader is unreachable,
// and Lookup and Result.Decode each keep the reader alive across their own
// use of the mapping, so a lookup in flight holds what it reads.
func (s *mmdbSource) reload() error {
	db, err := maxminddb.Open(s.path)
	if err != nil {
		return fmt.Errorf("opening the %s database %q: %w", s.kind, s.path, err)
	}
	s.db.Store(db)
	return nil
}

// reader is the database in force, nil once the source is closed.
func (s *mmdbSource) reader() *maxminddb.Reader {
	return s.db.Load()
}

// close releases the reader in force.
//
// This is the one Close the process makes, and it is safe because it runs
// after the decode workers have stopped -- ordering, not synchronization, is
// what rules out a concurrent lookup. Every reader a reload replaced is left
// to the runtime cleanup.
func (s *mmdbSource) close() error {
	db := s.db.Swap(nil)
	if db == nil {
		return nil
	}
	return db.Close()
}

// asnRecord is the shape the ASN databases publish. The field names are what
// both MaxMind GeoLite2-ASN and the DB-IP equivalent record.
type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
}

// countryRecord is the shape the country and city databases publish. The ISO
// code is what this exporter labels with: a country name is a display string
// that varies by locale and by database vendor.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// ASN fills the autonomous system numbers from a local database, for the
// devices that export flows without them.
//
// The lookup is a field rather than a method call so a test can drive the
// enrichment logic without a database file. The schema the production lookup
// decodes is MaxMind's contract, which no locally built fixture could
// validate anyway: a fixture written with these same tags would only agree
// with itself.
type ASN struct {
	counters
	mmdb   mmdbSource
	lookup func(netip.Addr) (uint32, bool)
}

// NewASN opens the ASN database at path.
func NewASN(path string) (*ASN, error) {
	a := &ASN{}
	a.mmdb.kind, a.mmdb.path = "ASN", path
	a.lookup = a.lookupDB

	if err := a.mmdb.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// newASNWithLookup builds an enricher over an arbitrary lookup, for tests.
func newASNWithLookup(lookup func(netip.Addr) (uint32, bool)) *ASN {
	return &ASN{lookup: lookup}
}

// Name implements Enricher.
func (a *ASN) Name() string {
	return "asn"
}

// Snapshot implements Enricher.
func (a *ASN) Snapshot() Snapshot {
	return a.snapshot(a.Name())
}

// Reload implements Reloader by re-reading the database file.
func (a *ASN) Reload() error {
	return a.mmdb.reload()
}

// Close releases the database.
func (a *ASN) Close() error {
	return a.mmdb.close()
}

// Enrich fills each side's autonomous system, and leaves a side the device
// already numbered alone.
//
// The two sides are accounted as one record: a lookup that filled either is
// a fill, and one that could resolve neither is unknown. A flow whose sides
// were both exported needs nothing.
func (a *ASN) Enrich(r *flow.Record) {
	if r.SrcAS != 0 && r.DstAS != 0 {
		a.skipped.Add(1)
		return
	}

	filled := false
	if r.SrcAS == 0 && r.SrcAddr.IsValid() {
		if as, ok := a.lookup(r.SrcAddr); ok {
			r.SrcAS = as
			filled = true
		}
	}
	if r.DstAS == 0 && r.DstAddr.IsValid() {
		if as, ok := a.lookup(r.DstAddr); ok {
			r.DstAS = as
			filled = true
		}
	}

	if filled {
		a.filled.Add(1)
		return
	}
	a.unknown.Add(1)
}

// lookupDB resolves one address against the database, reporting false where
// it carries no answer. Zero is not an answer: it is the value the record
// already had.
func (a *ASN) lookupDB(addr netip.Addr) (uint32, bool) {
	db := a.mmdb.reader()
	if db == nil {
		return 0, false
	}

	var record asnRecord
	if err := db.Lookup(addr).Decode(&record); err != nil {
		return 0, false
	}
	if record.Number == 0 {
		return 0, false
	}
	return record.Number, true
}

// Country fills the ISO country codes of each side from a local database.
// The lookup is a field for the reason ASN's is.
type Country struct {
	counters
	mmdb   mmdbSource
	lookup func(netip.Addr) (string, bool)
}

// NewCountry opens the country database at path.
func NewCountry(path string) (*Country, error) {
	c := &Country{}
	c.mmdb.kind, c.mmdb.path = "country", path
	c.lookup = c.lookupDB

	if err := c.mmdb.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// newCountryWithLookup builds an enricher over an arbitrary lookup, for tests.
func newCountryWithLookup(lookup func(netip.Addr) (string, bool)) *Country {
	return &Country{lookup: lookup}
}

// Name implements Enricher.
func (c *Country) Name() string {
	return "country"
}

// Snapshot implements Enricher.
func (c *Country) Snapshot() Snapshot {
	return c.snapshot(c.Name())
}

// Reload implements Reloader by re-reading the database file.
func (c *Country) Reload() error {
	return c.mmdb.reload()
}

// Close releases the database.
func (c *Country) Close() error {
	return c.mmdb.close()
}

// CountryPrivate is what a private address resolves to. It is not an ISO
// code and cannot collide with one, which are two upper-case letters.
//
// It exists because "the database could not place this" and "this address
// belongs to no country" are different answers that read the same. A LAN is
// the second, and it is a fact about the address rather than a gap in a
// database: no lookup can improve on it, and folding it in with the first
// leaves an operator unable to tell their own network from a database miss.
const CountryPrivate = "private"

// Enrich fills both sides' country codes. No flow protocol exports a country,
// so nothing here is ever skipped for a device reading.
func (c *Country) Enrich(r *flow.Record) {
	filled := false
	if r.SrcAddr.IsValid() {
		if code, ok := countryOf(r.SrcAddr, c.lookup); ok {
			r.SrcCountry = code
			filled = true
		}
	}
	if r.DstAddr.IsValid() {
		if code, ok := countryOf(r.DstAddr, c.lookup); ok {
			r.DstCountry = code
			filled = true
		}
	}

	if filled {
		c.filled.Add(1)
		return
	}
	c.unknown.Add(1)
}

// countryOf answers for an address the database cannot be asked about, and
// defers to it otherwise.
//
// Private means what netip means by it -- RFC 1918 and the IPv6 unique local
// range -- and nothing wider. Shared address space, loopback and link-local
// have no country either, but they are not private, and naming them so would
// be the guess this exists to avoid.
func countryOf(addr netip.Addr, lookup func(netip.Addr) (string, bool)) (string, bool) {
	if addr.IsPrivate() {
		return CountryPrivate, true
	}
	return lookup(addr)
}

// lookupDB resolves one address to its ISO code, reporting false where the
// database carries none. A reserved address resolves to nothing, which is
// correct: it belongs to no country.
func (c *Country) lookupDB(addr netip.Addr) (string, bool) {
	db := c.mmdb.reader()
	if db == nil {
		return "", false
	}

	var record countryRecord
	if err := db.Lookup(addr).Decode(&record); err != nil {
		return "", false
	}
	if record.Country.ISOCode == "" {
		return "", false
	}
	return record.Country.ISOCode, true
}
