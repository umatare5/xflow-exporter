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
	for i := range 420000 {
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

	// Random addresses rather than one repeated record. A single record
	// keeps both probes in L1 and every branch predicted, which reports a
	// figure several times faster than the traffic this ever sees.
	rng := rand.New(rand.NewPCG(1, 2))
	records := make([]flow.Record, benchRecords)
	for i := range records {
		records[i] = flow.Record{SrcAddr: randomAddr(rng), DstAddr: randomAddr(rng)}
	}

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		r := records[i&(benchRecords-1)]
		th.Enrich(&r)
	}
}

// benchRecords is a power of two, so the walk over them is a mask.
const benchRecords = 4096

func randomAddr(rng *rand.Rand) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(rng.UintN(256)), byte(rng.UintN(256)),
		byte(rng.UintN(256)), byte(rng.UintN(256)),
	})
}
