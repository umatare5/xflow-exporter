package enrich

import (
	"net/netip"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

var (
	publicSrc  = netip.MustParseAddr("198.51.100.7")
	publicDst  = netip.MustParseAddr("203.0.113.9")
	privateSrc = netip.MustParseAddr("10.0.0.1")
)

// asnTable builds a lookup over a fixed map, standing in for the database.
func asnTable(entries map[netip.Addr]uint32) func(netip.Addr) (uint32, bool) {
	return func(addr netip.Addr) (uint32, bool) {
		as, ok := entries[addr]
		return as, ok
	}
}

func countryTable(entries map[netip.Addr]string) func(netip.Addr) (string, bool) {
	return func(addr netip.Addr) (string, bool) {
		code, ok := entries[addr]
		return code, ok
	}
}

func TestASN_FillsBothSides(t *testing.T) {
	t.Parallel()

	a := newASNWithLookup(asnTable(map[netip.Addr]uint32{
		publicSrc: 64500,
		publicDst: 64501,
	}))

	r := flow.Record{SrcAddr: publicSrc, DstAddr: publicDst}
	a.Enrich(&r)

	if r.SrcAS != 64500 || r.DstAS != 64501 {
		t.Errorf("record = %d -> %d, want 64500 -> 64501", r.SrcAS, r.DstAS)
	}
	if got := a.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}
}

// TestASN_DeviceReadingWins pins the package rule on a side-by-side basis: a
// side the device numbered is left alone while the other is filled.
func TestASN_DeviceReadingWins(t *testing.T) {
	t.Parallel()

	a := newASNWithLookup(asnTable(map[netip.Addr]uint32{
		publicSrc: 64500,
		publicDst: 64501,
	}))

	r := flow.Record{SrcAddr: publicSrc, DstAddr: publicDst, SrcAS: 65000}
	a.Enrich(&r)

	if r.SrcAS != 65000 {
		t.Errorf("SrcAS = %d, want the device reading 65000 kept", r.SrcAS)
	}
	if r.DstAS != 64501 {
		t.Errorf("DstAS = %d, want the absent side filled", r.DstAS)
	}
}

// TestASN_BothSidesExportedIsSkipped pins that a fully numbered record costs
// no lookup at all.
func TestASN_BothSidesExportedIsSkipped(t *testing.T) {
	t.Parallel()

	lookups := 0
	a := newASNWithLookup(func(netip.Addr) (uint32, bool) {
		lookups++
		return 64500, true
	})

	r := flow.Record{SrcAddr: publicSrc, DstAddr: publicDst, SrcAS: 65000, DstAS: 65001}
	a.Enrich(&r)

	if lookups != 0 {
		t.Errorf("lookups = %d, want none for a record the device numbered", lookups)
	}
	if got := a.Snapshot(); got.Skipped != 1 {
		t.Errorf("Snapshot() = %+v, want one skipped", got)
	}
}

// TestASN_UnknownAddressesFillNothing pins that a database miss leaves the
// dimension absent rather than zero-filled.
func TestASN_UnknownAddressesFillNothing(t *testing.T) {
	t.Parallel()

	a := newASNWithLookup(asnTable(nil))

	r := flow.Record{SrcAddr: privateSrc, DstAddr: publicDst}
	a.Enrich(&r)

	if r.SrcAS != 0 || r.DstAS != 0 {
		t.Errorf("record = %d -> %d, want both absent", r.SrcAS, r.DstAS)
	}
	if got := a.Snapshot(); got.Unknown != 1 || got.Filled != 0 {
		t.Errorf("Snapshot() = %+v, want one unknown", got)
	}
}

// TestMMDB_AddresslessRecordsAreNotLookedUp covers the records that carry no
// address at all, a NetFlow v8 AS aggregate among them. A database answering
// for the zero address would otherwise place a flow that has no side.
func TestMMDB_AddresslessRecordsAreNotLookedUp(t *testing.T) {
	t.Parallel()

	seen := 0
	countSeen := func(addr netip.Addr) {
		if !addr.IsValid() {
			t.Errorf("the lookup saw the invalid address %v, want it guarded", addr)
		}
		seen++
	}

	a := newASNWithLookup(func(addr netip.Addr) (uint32, bool) {
		countSeen(addr)
		return 64500, true
	})
	c := newCountryWithLookup(func(addr netip.Addr) (string, bool) {
		countSeen(addr)
		return "JP", true
	})

	r := flow.Record{}
	a.Enrich(&r)
	c.Enrich(&r)

	if seen != 0 {
		t.Errorf("the lookups ran %d times, want none for a record with no address", seen)
	}
	if r.SrcAS != 0 || r.DstAS != 0 || r.SrcCountry != "" || r.DstCountry != "" {
		t.Errorf("record = %+v, want nothing filled", r)
	}
}

func TestCountry_FillsBothSides(t *testing.T) {
	t.Parallel()

	c := newCountryWithLookup(countryTable(map[netip.Addr]string{
		publicSrc: "JP",
		publicDst: "US",
	}))

	r := flow.Record{SrcAddr: publicSrc, DstAddr: publicDst}
	c.Enrich(&r)

	if r.SrcCountry != "JP" || r.DstCountry != "US" {
		t.Errorf("record = %q -> %q, want JP -> US", r.SrcCountry, r.DstCountry)
	}
	if got := c.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}
}

// TestCountry_OneSidePlacedIsStillAFill covers a flow leaving a private
// network: the internal side belongs to no country and stays absent.
func TestCountry_OneSidePlacedIsStillAFill(t *testing.T) {
	t.Parallel()

	c := newCountryWithLookup(countryTable(map[netip.Addr]string{publicDst: "US"}))

	r := flow.Record{SrcAddr: privateSrc, DstAddr: publicDst}
	c.Enrich(&r)

	if r.SrcCountry != "" {
		t.Errorf("SrcCountry = %q, want a private address placed nowhere", r.SrcCountry)
	}
	if r.DstCountry != "US" {
		t.Errorf("DstCountry = %q, want US", r.DstCountry)
	}
	if got := c.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}
}

func TestCountry_NeitherSidePlacedIsUnknown(t *testing.T) {
	t.Parallel()

	c := newCountryWithLookup(countryTable(nil))

	r := flow.Record{SrcAddr: privateSrc, DstAddr: privateSrc}
	c.Enrich(&r)

	if got := c.Snapshot(); got.Unknown != 1 || got.Filled != 0 {
		t.Errorf("Snapshot() = %+v, want one unknown", got)
	}
}

// TestMMDB_OpenFailsOnAMissingFile pins that a wrong path fails at startup
// rather than enriching nothing in silence.
func TestMMDB_OpenFailsOnAMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := NewASN(t.TempDir() + "/absent.mmdb"); err == nil {
		t.Error("NewASN() error = nil for a missing file, want it to fail")
	}
	if _, err := NewCountry(t.TempDir() + "/absent.mmdb"); err == nil {
		t.Error("NewCountry() error = nil for a missing file, want it to fail")
	}
}

// TestMMDB_CloseWithoutADatabase covers the test constructors' cleanup path.
func TestMMDB_CloseWithoutADatabase(t *testing.T) {
	t.Parallel()

	if err := newASNWithLookup(asnTable(nil)).Close(); err != nil {
		t.Errorf("ASN.Close() error = %v, want nil", err)
	}
	if err := newCountryWithLookup(countryTable(nil)).Close(); err != nil {
		t.Errorf("Country.Close() error = %v, want nil", err)
	}
}
