package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// TestMMDB_ReloadPicksUpANewFile pins the defect the reload closes: the
// databases are refreshed on disk by a cron job, and until a reload re-read
// them the process kept answering from the file it opened at startup.
func TestMMDB_ReloadPicksUpANewFile(t *testing.T) {
	t.Parallel()

	path := asnFixture(t, 64500)
	a, err := NewASN(path)
	if err != nil {
		t.Fatalf("NewASN() error = %v, want nil", err)
	}

	if as, ok := a.lookup(publicSrc); !ok || as != 64500 {
		t.Fatalf("lookup = %d %v, want 64500 true", as, ok)
	}

	replaceMMDB(t, path, asnFixture(t, 64501))
	if err := a.Reload(); err != nil {
		t.Fatalf("Reload() error = %v, want nil", err)
	}

	if as, ok := a.lookup(publicSrc); !ok || as != 64501 {
		t.Errorf("lookup = %d %v after a reload, want 64501 true", as, ok)
	}
}

// TestMMDB_FailedReloadKeepsTheDatabaseInForce pins that a truncated download
// leaves the previous database serving rather than turning every lookup into
// a miss, which would read as absence the operator cannot tell from a real
// one.
func TestMMDB_FailedReloadKeepsTheDatabaseInForce(t *testing.T) {
	t.Parallel()

	path := countryFixture(t, "JP")
	c, err := NewCountry(path)
	if err != nil {
		t.Fatalf("NewCountry() error = %v, want nil", err)
	}

	// The fetch script installs by rename, so a bad download replaces the
	// directory entry and leaves the inode the reader mapped untouched.
	corrupt := filepath.Join(t.TempDir(), "corrupt.mmdb")
	if err := os.WriteFile(corrupt, []byte("a captive portal login page"), 0o600); err != nil {
		t.Fatalf("writing the replacement: %v", err)
	}
	if err := os.Rename(corrupt, path); err != nil {
		t.Fatalf("installing the replacement: %v", err)
	}

	if err := c.Reload(); err == nil {
		t.Fatal("Reload() error = nil for an unreadable database, want it reported")
	}

	if code, ok := c.lookup(publicSrc); !ok || code != "JP" {
		t.Errorf("lookup = %q %v after a failed reload, want the previous JP true", code, ok)
	}
}

// TestMMDB_LookupsSurviveConcurrentReloads is the test the design exists for.
// A reload replaces a memory-mapped reader; closing the one it replaced
// unmaps a region the decode workers may be reading, and that faults rather
// than erroring. Run under -race.
func TestMMDB_LookupsSurviveConcurrentReloads(t *testing.T) {
	t.Parallel()

	asnPath := asnFixture(t, 64500)
	countryPath := countryFixture(t, "JP")

	a, err := NewASN(asnPath)
	if err != nil {
		t.Fatalf("NewASN() error = %v, want nil", err)
	}
	c, err := NewCountry(countryPath)
	if err != nil {
		t.Fatalf("NewCountry() error = %v, want nil", err)
	}

	chain := NewChain(a, c)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Readers stand in for the decode workers.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := flow.Record{SrcAddr: publicSrc, DstAddr: publicDst}
				chain.Enrich([]flow.Record{r})
			}
		}()
	}

	// Reloaders stand in for the management endpoint and SIGHUP together.
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := chain.Reload(); err != nil {
					t.Errorf("Reload() error = %v, want nil", err)
					return
				}
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	// A close after the readers stop is the shutdown ordering, and it must
	// still release the reader in force.
	chain.Close()
	if got := a.mmdb.reader(); got != nil {
		t.Errorf("reader after Close() = %p, want nil", got)
	}
}

// TestMMDB_LookupAfterCloseIsAMiss covers the reader the close left behind.
// A miss leaves the dimension absent, which is what a source that knows
// nothing is; a nil reader would fault instead.
func TestMMDB_LookupAfterCloseIsAMiss(t *testing.T) {
	t.Parallel()

	a, err := NewASN(asnFixture(t, 64500))
	if err != nil {
		t.Fatalf("NewASN() error = %v, want nil", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}

	r := flow.Record{SrcAddr: publicSrc, DstAddr: publicDst}
	a.Enrich(&r)

	if r.SrcAS != 0 || r.DstAS != 0 {
		t.Errorf("record = %d -> %d, want both absent", r.SrcAS, r.DstAS)
	}
}
