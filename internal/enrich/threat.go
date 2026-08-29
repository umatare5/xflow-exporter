// This file flags addresses listed in files held on local disk.

package enrich

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// maxThreatLineLength bounds one line of a list file. An address is far
// shorter than this, so a longer line says the file is not a list, and the
// bound is that assertion rather than a memory guard -- bufio.Scanner already
// stops at 64 KiB on its own.
//
// It is the scanner's buffer, which has to hold the line separator too, so
// the longest line that loads is one byte shorter.
const maxThreatLineLength = 256

// threatSet is one immutable snapshot of the flagged addresses. It is
// replaced wholesale on reload rather than mutated, so a lookup never sees a
// half-loaded set and never takes a lock.
type threatSet struct {
	addresses map[netip.Addr]struct{}
	// sources is how many files went into this set, entries how many
	// distinct addresses came out, and skipped how many lines were not an
	// address at all.
	sources int
	entries int
	skipped int
}

// Threat flags addresses listed in files this exporter reads from disk.
//
// Nothing is downloaded and nothing is sent. The lists are fetched by
// whatever the operator already uses for the MaxMind databases, and a reload
// picks up what that left behind. That keeps every address inside the host
// and keeps a third party's latency off the decode path entirely.
type Threat struct {
	counters
	paths []string

	set atomic.Pointer[threatSet]

	reloads  atomic.Uint64
	failures atomic.Uint64
}

// NewThreat reads the given list files into the first snapshot. A file that
// cannot be read fails startup: an exporter flagging nothing looks exactly
// like one whose lists held nothing.
func NewThreat(paths []string) (*Threat, error) {
	t := &Threat{paths: paths}
	if err := t.Reload(); err != nil {
		return nil, err
	}
	return t, nil
}

// Name implements Enricher.
func (t *Threat) Name() string {
	return "threat"
}

// Snapshot implements Enricher.
func (t *Threat) Snapshot() Snapshot {
	return t.snapshot(t.Name())
}

// Reload rebuilds the set from the configured files.
//
// The new set is built whole before it replaces the old one, so a reload of
// a large list never leaves a lookup consulting a partial set, and a file
// that has gone missing leaves the previous snapshot in place rather than
// unflagging every address at once.
func (t *Threat) Reload() error {
	addresses := make(map[netip.Addr]struct{})

	skipped := 0
	for _, path := range t.paths {
		n, err := readThreatFile(path, addresses)
		if err != nil {
			t.failures.Add(1)
			return err
		}
		skipped += n
	}

	// A skipped line is coverage this exporter does not have. Prefixes are
	// the usual reason, since a list published in CIDR notation loads only
	// its bare addresses, and silence about that reads as full coverage.
	if skipped > 0 {
		slog.Warn("Skipped threat list lines that are not an address",
			"skipped", skipped, "loaded", len(addresses))
	}

	t.set.Store(&threatSet{
		addresses: addresses,
		sources:   len(t.paths),
		entries:   len(addresses),
		skipped:   skipped,
	})
	t.reloads.Add(1)
	return nil
}

// Stats reports the reload outcomes and the size of the set in force.
func (t *Threat) Stats() ThreatStats {
	set := t.set.Load()
	stats := ThreatStats{
		Reloads:  t.reloads.Load(),
		Failures: t.failures.Load(),
	}
	if set != nil {
		stats.Sources = set.sources
		stats.Entries = set.entries
		stats.Skipped = set.skipped
	}
	return stats
}

// ThreatStats is the reload accounting a scrape reads.
type ThreatStats struct {
	Reloads  uint64
	Failures uint64
	Sources  int
	Entries  int
	Skipped  int
}

// Enrich flags each side listed in the set in force.
//
// A record neither side of which is listed counts as unknown rather than as
// a finding: an unlisted address is one no list covers, which is absence and
// not a clean bill of health.
func (t *Threat) Enrich(r *flow.Record) {
	set := t.set.Load()
	if set == nil {
		t.unknown.Add(1)
		return
	}

	flagged := false
	if _, listed := set.addresses[r.SrcAddr]; listed {
		r.SrcFlagged = true
		flagged = true
	}
	if _, listed := set.addresses[r.DstAddr]; listed {
		r.DstFlagged = true
		flagged = true
	}

	if flagged {
		t.filled.Add(1)
		return
	}
	t.unknown.Add(1)
}

// readThreatFile adds one file's addresses to the set.
//
// The format is one address per line, which is what every published list
// this is meant to read uses. A comment, a blank line, and any trailing
// field after whitespace or a comma are skipped, so a CSV export of the same
// data loads without a converter. A line that is not an address is skipped
// rather than failing the file: one malformed row must not cost the other
// quarter of a million.
func readThreatFile(path string, into map[netip.Addr]struct{}) (int, error) {
	// The path is a flag the operator set, the same trust as the database
	// paths beside it. Nothing on the wire reaches it.
	file, err := os.Open(path) //nolint:gosec // The path is operator configuration.
	if err != nil {
		return 0, fmt.Errorf("opening the threat list %q: %w", path, err)
	}
	defer closeList(file, path)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, maxThreatLineLength), maxThreatLineLength)

	skipped := 0
	for scanner.Scan() {
		addr, ok := parseThreatLine(scanner.Text())
		if !ok {
			// A blank line and a comment are not coverage anyone expected,
			// so only a line that carried something counts as skipped.
			if carriesValue(scanner.Text()) {
				skipped++
			}
			continue
		}
		into[addr] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading the threat list %q: %w", path, err)
	}
	return skipped, nil
}

// carriesValue reports whether a line was meant to name something, which is
// what separates a line the file skipped from its blanks and its comments.
func carriesValue(line string) bool {
	line = strings.TrimSpace(line)
	return line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";")
}

// closeList releases one list file. The addresses have been read by then, so
// a close failure changes nothing for the caller.
func closeList(file *os.File, path string) {
	if err := file.Close(); err != nil {
		slog.Debug("Failed to close a threat list", "path", path, "error", err)
	}
}

// parseThreatLine reads one address from one line, reporting false for a
// line that carries none.
func parseThreatLine(line string) (netip.Addr, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return netip.Addr{}, false
	}

	// Keep the first field, so a CSV row or an address with a trailing
	// comment loads the same as a bare address.
	if cut := strings.IndexAny(line, " \t,;"); cut >= 0 {
		line = line[:cut]
	}

	addr, err := netip.ParseAddr(line)
	if err != nil {
		return netip.Addr{}, false
	}

	// An address carrying a zone is a link-local one scoped to an interface
	// of the host that wrote it, which cannot match a flow record here.
	//
	// Unmap because the decoder unmaps: a list naming ::ffff:198.51.100.7
	// means the address every record spells 198.51.100.7, and netip holds
	// the two as distinct keys, so a mapped entry would match nothing.
	return addr.WithZone("").Unmap(), true
}
