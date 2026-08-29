package enrich

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// The MaxMind format, only as much of it as one record needs. A fixture is
// not evidence about the schema -- the production tags are MaxMind's contract
// and a locally built file would only agree with itself -- but the reload
// hazard is the mapping's lifetime, not the schema, and that needs a file the
// library really mmaps.
const (
	fixtureNodeCount  = 1
	fixtureRecordSize = 24
	fixtureTreeBytes  = fixtureNodeCount * fixtureRecordSize / 4
	fixtureSeparator  = 16
)

var fixtureMarker = []byte("\xAB\xCD\xEFMaxMind.com")

// mmdbString encodes one UTF-8 string.
func mmdbString(s string) []byte {
	return append(mmdbControl(2, len(s)), s...)
}

// mmdbUint32 encodes one unsigned integer in as few bytes as it needs.
func mmdbUint32(v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	trimmed := buf[:]
	for len(trimmed) > 0 && trimmed[0] == 0 {
		trimmed = trimmed[1:]
	}
	return append(mmdbControl(6, len(trimmed)), trimmed...)
}

// mmdbMap encodes a map of the given size; the pairs follow.
func mmdbMap(size int) []byte {
	return mmdbControl(7, size)
}

// mmdbControl writes the control byte for a type that fits in the short form.
func mmdbControl(kind, size int) []byte {
	if size >= 29 {
		panic("the fixture encoder only writes the short size form")
	}
	return []byte{byte(kind<<5) | byte(size)}
}

// concat joins the pieces of an encoded section.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// writeMMDB assembles a one-record IPv4 database answering every address with
// data, and writes it to a file the test owns.
func writeMMDB(t *testing.T, name string, data []byte) string {
	t.Helper()

	// Both records of the only node point at the first byte of the data
	// section: offset 0 encodes as node_count + 16.
	pointer := uint32(fixtureNodeCount + fixtureSeparator)
	var record [4]byte
	binary.BigEndian.PutUint32(record[:], pointer)

	tree := concat(record[1:], record[1:])
	if len(tree) != fixtureTreeBytes {
		t.Fatalf("tree = %d bytes, want %d", len(tree), fixtureTreeBytes)
	}

	metadata := concat(
		mmdbMap(5),
		mmdbString("node_count"), mmdbUint32(fixtureNodeCount),
		mmdbString("record_size"), mmdbUint32(fixtureRecordSize),
		mmdbString("ip_version"), mmdbUint32(4),
		mmdbString("database_type"), mmdbString("Test"),
		mmdbString("binary_format_major_version"), mmdbUint32(2),
	)

	file := concat(tree, make([]byte, fixtureSeparator), data, fixtureMarker, metadata)

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

// asnFixture writes a database answering every address with one AS number.
func asnFixture(t *testing.T, as uint32) string {
	t.Helper()

	return writeMMDB(t, "asn.mmdb", concat(
		mmdbMap(1),
		mmdbString("autonomous_system_number"), mmdbUint32(as),
	))
}

// countryFixture writes a database answering every address with one ISO code.
func countryFixture(t *testing.T, code string) string {
	t.Helper()

	return writeMMDB(t, "country.mmdb", concat(
		mmdbMap(1),
		mmdbString("country"),
		mmdbMap(1),
		mmdbString("iso_code"), mmdbString(code),
	))
}

// replaceMMDB installs src at dst the way the fetch script does: by rename,
// which swaps the directory entry and leaves the inode a live reader mapped
// alone. Writing over the file in place would change the bytes under an open
// mapping instead.
func replaceMMDB(t *testing.T, dst, src string) {
	t.Helper()

	if err := os.Rename(src, dst); err != nil {
		t.Fatalf("installing the replacement: %v", err)
	}
}
