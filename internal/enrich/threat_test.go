package enrich

import (
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// writeList writes one list file and returns its path.
func writeList(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestThreat_FlagsListedAddresses(t *testing.T) {
	t.Parallel()

	path := writeList(t, "list.txt", "198.51.100.7\n2001:db8::1\n")

	th, err := NewThreat([]string{path})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	r := flow.Record{
		SrcAddr: netip.MustParseAddr("198.51.100.7"),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
	}
	th.Enrich(&r)

	if !r.SrcFlagged {
		t.Error("SrcFlagged = false for a listed address, want true")
	}
	if r.DstFlagged {
		t.Error("DstFlagged = true for an unlisted address, want false")
	}
	if got := th.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}

	// IPv6 is flagged from the same set.
	r = flow.Record{SrcAddr: netip.MustParseAddr("2001:db8::1")}
	th.Enrich(&r)
	if !r.SrcFlagged {
		t.Error("SrcFlagged = false for a listed IPv6 address, want true")
	}
}

// TestThreat_MappedListEntryMatchesTheUnmappedRecord crosses the boundary the
// decoder and the list meet at. The decoder unmaps every address it reads, so
// a list naming the IPv4-mapped form has to be normalized the same way or it
// keys a value no record can ever carry -- and the line parses, so the skipped
// count reports full coverage over the gap.
func TestThreat_MappedListEntryMatchesTheUnmappedRecord(t *testing.T) {
	t.Parallel()

	path := writeList(t, "mapped.txt", "::ffff:198.51.100.7\n203.0.113.9\n")

	th, err := NewThreat([]string{path})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	// What the decoder produces for both spellings on the wire.
	r := flow.Record{
		SrcAddr: netip.MustParseAddr("::ffff:198.51.100.7").Unmap(),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
	}
	th.Enrich(&r)

	if !r.SrcFlagged {
		t.Error("SrcFlagged = false for an address the list names in mapped form, want true")
	}
	if !r.DstFlagged {
		t.Error("DstFlagged = false for a plainly listed address, want true")
	}

	// Both spellings collapse to one key, so the set holds two addresses.
	if got := th.Stats().Entries; got != 2 {
		t.Errorf("Entries = %d, want the two distinct addresses", got)
	}
}

// TestThreat_FlagsTheDestinationSide pins the side the outgoing lists exist
// for: a hit on the destination is an inside host that reached a listed
// address, which the source-side lists cannot see.
func TestThreat_FlagsTheDestinationSide(t *testing.T) {
	t.Parallel()

	th, err := NewThreat([]string{writeList(t, "list.txt", "198.51.100.7\n")})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	r := flow.Record{
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("198.51.100.7"),
	}
	th.Enrich(&r)

	if r.SrcFlagged {
		t.Error("SrcFlagged = true for an unlisted inside host, want false")
	}
	if !r.DstFlagged {
		t.Error("DstFlagged = false for a listed destination, want true")
	}
	if got := th.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}
}

// TestThreat_UnlistedIsAbsenceNotAVerdict pins the reading: an address no
// list covers is unknown rather than found clean.
func TestThreat_UnlistedIsAbsenceNotAVerdict(t *testing.T) {
	t.Parallel()

	th, err := NewThreat([]string{writeList(t, "list.txt", "198.51.100.7\n")})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	r := flow.Record{
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
	}
	th.Enrich(&r)

	if r.SrcFlagged || r.DstFlagged {
		t.Errorf("record = %+v, want nothing flagged", r)
	}
	if got := th.Snapshot(); got.Unknown != 1 || got.Filled != 0 {
		t.Errorf("Snapshot() = %+v, want one unknown", got)
	}
}

// TestThreat_ParsesThePublishedFormats covers what the lists this reads
// actually contain, and the rows that must be skipped rather than fail.
func TestThreat_ParsesThePublishedFormats(t *testing.T) {
	t.Parallel()

	content := strings.Join([]string{
		"# a comment header",
		"; another comment style",
		"",
		"   ",
		"198.51.100.7",
		"  203.0.113.9  ",              // surrounding whitespace
		"192.0.2.1 # a trailing note",  // trailing comment
		"2026-08-26,user,ip,192.0.2.2", // a CSV row keeps its first field
		"192.0.2.3\t10",                // tab separated
		"not-an-address",               // skipped, not fatal
		"999.999.999.999",              // skipped, not fatal
		"2001:db8::2",
	}, "\n")

	th, err := NewThreat([]string{writeList(t, "mixed.txt", content)})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	// The CSV row's first field is a date rather than an address, so it is
	// skipped: only the rows whose first field parses are taken.
	for _, want := range []string{"198.51.100.7", "203.0.113.9", "192.0.2.1", "192.0.2.3", "2001:db8::2"} {
		r := flow.Record{SrcAddr: netip.MustParseAddr(want)}
		th.Enrich(&r)
		if !r.SrcFlagged {
			t.Errorf("%s was not flagged, want it read from the list", want)
		}
	}

	stats := th.Stats()
	if stats.Entries != 5 {
		t.Errorf("Entries = %d, want the five parseable addresses", stats.Entries)
	}
	// The CSV date, the two unparseable rows: blanks and comments are not
	// coverage anyone expected, so they are not counted as skipped.
	if stats.Skipped != 3 {
		t.Errorf("Skipped = %d, want the three rows that named no address", stats.Skipped)
	}
}

// TestThreat_PrefixLinesAreCountedAsSkipped pins what a list published in
// CIDR notation does here: its prefixes load nothing, and the count says so
// rather than leaving the gap silent.
func TestThreat_PrefixLinesAreCountedAsSkipped(t *testing.T) {
	t.Parallel()

	content := "198.51.100.7\n203.0.113.0/24\n2001:db8::/32\n"

	th, err := NewThreat([]string{writeList(t, "prefixes.txt", content)})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	r := flow.Record{SrcAddr: netip.MustParseAddr("203.0.113.9")}
	th.Enrich(&r)
	if r.SrcFlagged {
		t.Error("an address inside a listed prefix was flagged, want prefixes unmatched")
	}

	stats := th.Stats()
	if stats.Entries != 1 || stats.Skipped != 2 {
		t.Errorf("Entries, Skipped = %d, %d; want 1, 2", stats.Entries, stats.Skipped)
	}
}

// TestThreat_MergesEverySource pins that several files become one set, which
// is what makes combining the published lists worthwhile.
func TestThreat_MergesEverySource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := filepath.Join(dir, "a.txt")
	second := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(first, []byte("198.51.100.7\n192.0.2.1\n"), 0o600); err != nil {
		t.Fatalf("writing a.txt: %v", err)
	}
	// The overlap must be deduplicated rather than counted twice.
	if err := os.WriteFile(second, []byte("192.0.2.1\n203.0.113.9\n"), 0o600); err != nil {
		t.Fatalf("writing b.txt: %v", err)
	}

	th, err := NewThreat([]string{first, second})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	stats := th.Stats()
	if stats.Sources != 2 {
		t.Errorf("Sources = %d, want 2", stats.Sources)
	}
	if stats.Entries != 3 {
		t.Errorf("Entries = %d, want the three distinct addresses", stats.Entries)
	}
}

// TestThreat_ReloadReplacesTheSet covers the reload path the management
// endpoint drives.
func TestThreat_ReloadReplacesTheSet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatalf("writing the list: %v", err)
	}

	th, err := NewThreat([]string{path})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	// The list is refreshed by whatever fetches it, then reloaded.
	if err := os.WriteFile(path, []byte("203.0.113.9\n"), 0o600); err != nil {
		t.Fatalf("rewriting the list: %v", err)
	}
	if err := th.Reload(); err != nil {
		t.Fatalf("Reload() error = %v, want nil", err)
	}

	r := flow.Record{
		SrcAddr: netip.MustParseAddr("203.0.113.9"),
		DstAddr: netip.MustParseAddr("198.51.100.7"),
	}
	th.Enrich(&r)

	if !r.SrcFlagged {
		t.Error("the newly listed address was not flagged, want the reload applied")
	}
	if r.DstFlagged {
		t.Error("the removed address was still flagged, want the old set replaced")
	}
	if got := th.Stats().Reloads; got != 2 {
		t.Errorf("Reloads = %d, want the initial load and the reload", got)
	}
}

// TestThreat_FailedReloadKeepsTheOldSet is the property the whole design
// rests on: a list that has gone missing must not unflag every address at
// once, which would read as a network that had just gone clean.
func TestThreat_FailedReloadKeepsTheOldSet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatalf("writing the list: %v", err)
	}

	th, err := NewThreat([]string{path})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the list: %v", err)
	}
	if err := th.Reload(); err == nil {
		t.Fatal("Reload() error = nil for a missing file, want it reported")
	}

	r := flow.Record{SrcAddr: netip.MustParseAddr("198.51.100.7")}
	th.Enrich(&r)
	if !r.SrcFlagged {
		t.Error("the address was unflagged after a failed reload, want the old set kept")
	}

	stats := th.Stats()
	if stats.Failures != 1 {
		t.Errorf("Failures = %d, want 1", stats.Failures)
	}
	if stats.Entries != 1 {
		t.Errorf("Entries = %d, want the previous set still in force", stats.Entries)
	}
}

// TestThreat_MissingFileFailsStartup pins that a typo in a path is caught at
// start rather than flagging nothing in silence.
func TestThreat_MissingFileFailsStartup(t *testing.T) {
	t.Parallel()

	if _, err := NewThreat([]string{filepath.Join(t.TempDir(), "absent.txt")}); err == nil {
		t.Error("NewThreat() error = nil for a missing file, want it refused")
	}
}

// TestThreat_OverlongLineIsRejected covers the guard against reading a file
// that is not a list at all.
func TestThreat_OverlongLineIsRejected(t *testing.T) {
	t.Parallel()

	path := writeList(t, "huge.txt", strings.Repeat("a", maxThreatLineLength*4)+"\n")

	if _, err := NewThreat([]string{path}); err == nil {
		t.Error("NewThreat() error = nil for an overlong line, want it refused")
	}
}

// TestThreat_OverlongLineCostsTheWholeFile settles which of two readings the
// length bound carries, since a file whose only line is overlong satisfies
// both. The bound asserts a format rather than skipping a row: the scanner
// cannot resynchronize past a line it would not hold, so what follows is
// unread, and a set silently missing its tail under-flags -- which reads as a
// clean address rather than an uncovered one.
func TestThreat_OverlongLineCostsTheWholeFile(t *testing.T) {
	t.Parallel()

	path := writeList(t, "mixed.txt", "198.51.100.7\n"+
		strings.Repeat("z", maxThreatLineLength+8)+"\n"+
		"203.0.113.9\n")

	if _, err := NewThreat([]string{path}); err == nil {
		t.Error("NewThreat() error = nil for a list with one overlong row, want the file refused")
	}
}

// TestThreat_ReloadIsSafeUnderLookups pins that a reload never leaves a
// lookup consulting a partial set.
func TestThreat_ReloadIsSafeUnderLookups(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatalf("writing the list: %v", err)
	}

	th, err := NewThreat([]string{path})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r := flow.Record{SrcAddr: netip.MustParseAddr("198.51.100.7")}
					th.Enrich(&r)
				}
			}
		}()
	}

	for range 50 {
		if err := th.Reload(); err != nil {
			t.Errorf("Reload() error = %v, want nil", err)
			break
		}
	}

	close(stop)
	wg.Wait()
}

func BenchmarkThreat_Enrich(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "list.txt")

	// A set the size of the published lists combined.
	var builder strings.Builder
	for i := range benchEntries {
		builder.WriteString(netip.AddrFrom4([4]byte{
			byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i),
		}).String())
		builder.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		b.Fatalf("writing the list: %v", err)
	}

	th, err := NewThreat([]string{path})
	if err != nil {
		b.Fatalf("NewThreat() error = %v, want nil", err)
	}

	// Both branches, because they cost differently and a uniform probe over
	// the address space resolves a hit about once in ten thousand runs: an
	// all-miss benchmark never executes the half that flags anything.
	for _, bb := range []struct {
		name    string
		records []flow.Record
	}{
		{"miss", benchRecordsMissing()},
		{"hit", benchRecordsListed()},
	} {
		b.Run(bb.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				// By pointer: copying the record under measurement costs
				// more than the lookup it is measuring.
				th.Enrich(&bb.records[i&(benchRecords-1)])
			}
		})
	}
}

const (
	// benchEntries is the measured size of the published lists combined, so
	// the figure is the one a deployment sees rather than a favorable point
	// on the map's fill curve.
	benchEntries = 420000
	// benchRecords is a power of two, so the walk over them is a mask.
	benchRecords = 4096
)

// benchRecordsMissing draws addresses uniformly, which is what the traffic
// does: almost nothing is listed.
func benchRecordsMissing() []flow.Record {
	rng := rand.New(rand.NewPCG(1, 2))
	records := make([]flow.Record, benchRecords)
	for i := range records {
		records[i] = flow.Record{SrcAddr: randomAddr(rng), DstAddr: randomAddr(rng)}
	}
	return records
}

// benchRecordsListed draws from the set, so every lookup resolves.
func benchRecordsListed() []flow.Record {
	rng := rand.New(rand.NewPCG(3, 4))
	records := make([]flow.Record, benchRecords)
	for i := range records {
		records[i] = flow.Record{SrcAddr: listedAddr(rng), DstAddr: listedAddr(rng)}
	}
	return records
}

func randomAddr(rng *rand.Rand) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(rng.UintN(256)), byte(rng.UintN(256)),
		byte(rng.UintN(256)), byte(rng.UintN(256)),
	})
}

// listedAddr mirrors how the fixture above builds its keys.
func listedAddr(rng *rand.Rand) netip.Addr {
	i := rng.UintN(benchEntries)
	return netip.AddrFrom4([4]byte{
		byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i),
	})
}
