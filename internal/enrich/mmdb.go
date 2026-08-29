// Package enrich fills flow record dimensions the exporting device did not
// carry, from sources local to this exporter.
// This file reads MaxMind-format databases held on local disk.
package enrich

import (
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

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
	db     *maxminddb.Reader
	lookup func(netip.Addr) (uint32, bool)
}

// NewASN opens the ASN database at path.
func NewASN(path string) (*ASN, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening the ASN database %q: %w", path, err)
	}

	a := &ASN{db: db}
	a.lookup = a.lookupDB
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

// Close releases the database.
func (a *ASN) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Close()
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
	var record asnRecord
	if err := a.db.Lookup(addr).Decode(&record); err != nil {
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
	db     *maxminddb.Reader
	lookup func(netip.Addr) (string, bool)
}

// NewCountry opens the country database at path.
func NewCountry(path string) (*Country, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening the country database %q: %w", path, err)
	}

	c := &Country{db: db}
	c.lookup = c.lookupDB
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

// Close releases the database.
func (c *Country) Close() error {
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Enrich fills both sides' country codes. No flow protocol exports a country,
// so nothing here is ever skipped for a device reading.
func (c *Country) Enrich(r *flow.Record) {
	filled := false
	if r.SrcAddr.IsValid() {
		if code, ok := c.lookup(r.SrcAddr); ok {
			r.SrcCountry = code
			filled = true
		}
	}
	if r.DstAddr.IsValid() {
		if code, ok := c.lookup(r.DstAddr); ok {
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

// lookupDB resolves one address to its ISO code, reporting false where the
// database carries none. A private or reserved address resolves to nothing,
// which is correct: it belongs to no country.
func (c *Country) lookupDB(addr netip.Addr) (string, bool) {
	var record countryRecord
	if err := c.db.Lookup(addr).Decode(&record); err != nil {
		return "", false
	}
	if record.Country.ISOCode == "" {
		return "", false
	}
	return record.Country.ISOCode, true
}
