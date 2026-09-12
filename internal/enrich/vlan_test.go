package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// fixtureVLANs nests 10.0.0.0/8 around 10.1.0.0/16 and 10.1.1.0/24 on one
// device, and gives a second device its own numbering of one of them.
const fixtureVLANs = `devices:
  192.0.2.1:
    hostname: sw1.example.net
    vlans:
      10:
        name: campus
        prefixes:
          - 10.0.0.0/8
      20:
        name: servers
        prefixes:
          - 10.1.0.0/16
          - 2001:db8:20::/48
      30:
        prefixes: [10.1.1.0/24]
  192.0.2.2:
    vlans:
      99:
        name: other-site
        prefixes: [10.1.1.0/24]
`

// vlanFixture loads the fixture and returns the enricher over it.
func vlanFixture(t *testing.T) *VLAN {
	t.Helper()

	return NewVLAN(loadMapping(t, fixtureVLANs))
}

// enrichBetween runs one record between two addresses of one device.
func enrichBetween(v *VLAN, exporter, src, dst string) flow.Record {
	r := flow.Record{
		Exporter: netip.MustParseAddr(exporter),
		SrcAddr:  netip.MustParseAddr(src),
		DstAddr:  netip.MustParseAddr(dst),
	}
	v.Enrich(&r)
	return r
}

// TestVLAN_LongestPrefixWins pins the rule the whole table is ordered for. A
// network is written as a wide allocation with narrower segments carved out
// of it, so an address inside two of them belongs to the narrower: matching
// the wider one would put a host on the summary route it is reached through.
func TestVLAN_LongestPrefixWins(t *testing.T) {
	t.Parallel()

	v := vlanFixture(t)

	for _, tt := range []struct {
		address string
		want    uint16
	}{
		{"10.1.1.7", 30}, // inside all three
		{"10.1.2.7", 20}, // inside /8 and /16
		{"10.2.0.7", 10}, // inside /8 alone
		{"192.0.2.7", 0}, // inside none
	} {
		r := enrichBetween(v, "192.0.2.1", tt.address, "203.0.113.7")
		if r.SrcVLAN != tt.want {
			t.Errorf("SrcVLAN(%s) = %d, want %d", tt.address, r.SrcVLAN, tt.want)
		}
	}
}

// TestVLAN_EachDeviceReadsItsOwnTable pins that the exporter is part of the
// lookup. One prefix may be a different VLAN behind each device, and a device
// the file says nothing about must resolve nothing rather than borrow the
// numbering of the device beside it.
func TestVLAN_EachDeviceReadsItsOwnTable(t *testing.T) {
	t.Parallel()

	v := vlanFixture(t)

	if got := enrichBetween(v, "192.0.2.2", "10.1.1.7", "203.0.113.7"); got.SrcVLAN != 99 {
		t.Errorf("SrcVLAN = %d, want 99: the second device numbers the prefix its own way", got.SrcVLAN)
	}
	if got := enrichBetween(v, "192.0.2.9", "10.1.1.7", "203.0.113.7"); got.SrcVLAN != 0 {
		t.Errorf("SrcVLAN = %d, want 0: the file holds no table for that device", got.SrcVLAN)
	}
	if got := v.Snapshot(); got.Unknown != 1 || got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled and one unknown", got)
	}
}

// TestVLAN_ResolvesBothFamilies pins that a device's IPv6 prefixes resolve
// beside its IPv4 ones, and that an IPv6 address outside all of them reads
// zero rather than the VLAN of a numerically similar IPv4 prefix.
func TestVLAN_ResolvesBothFamilies(t *testing.T) {
	t.Parallel()

	v := vlanFixture(t)

	got := enrichBetween(v, "192.0.2.1", "2001:db8:20::7", "2001:db8:99::7")
	if got.SrcVLAN != 20 || got.DstVLAN != 0 {
		t.Errorf("VLANs = %d -> %d, want 20 -> 0", got.SrcVLAN, got.DstVLAN)
	}
}

// TestVLAN_OneSideIsAFill covers the traffic this source exists for: a flow
// between a local segment and the internet resolves on one side only, and
// that is an answer rather than a miss.
func TestVLAN_OneSideIsAFill(t *testing.T) {
	t.Parallel()

	v := vlanFixture(t)

	got := enrichBetween(v, "192.0.2.1", "203.0.113.7", "10.1.2.7")
	if got.SrcVLAN != 0 || got.DstVLAN != 20 {
		t.Errorf("VLANs = %d -> %d, want 0 -> 20", got.SrcVLAN, got.DstVLAN)
	}
	if snap := v.Snapshot(); snap.Filled != 1 || snap.Unknown != 0 {
		t.Errorf("Snapshot() = %+v, want one filled", snap)
	}
}

// TestVLAN_NeitherSideIsUnknown pins the counterpart: a flow between two
// foreign addresses leaves both sides at zero and counts as unknown, which is
// what keeps the pair table to the traffic the file can place.
func TestVLAN_NeitherSideIsUnknown(t *testing.T) {
	t.Parallel()

	v := vlanFixture(t)

	got := enrichBetween(v, "192.0.2.1", "203.0.113.7", "198.51.100.7")
	if got.SrcVLAN != 0 || got.DstVLAN != 0 {
		t.Errorf("VLANs = %d -> %d, want both zero", got.SrcVLAN, got.DstVLAN)
	}
	if snap := v.Snapshot(); snap.Unknown != 1 || snap.Filled != 0 {
		t.Errorf("Snapshot() = %+v, want one unknown", snap)
	}
}

// TestVLAN_AnUnnamedVLANStillResolves pins that the two halves are separate.
// A VLAN carries prefixes to be useful and a name only to be readable, so one
// written without a name keys its counters and reaches no naming series.
func TestVLAN_AnUnnamedVLANStillResolves(t *testing.T) {
	t.Parallel()

	mapping := loadMapping(t, fixtureVLANs)

	if got := NewVLAN(mapping); enrichBetween(got, "192.0.2.1", "10.1.1.7", "203.0.113.7").SrcVLAN != 30 {
		t.Error("the unnamed VLAN resolved nothing, want it to key its counters")
	}

	named := map[VLANRef]string{}
	for ref, name := range mapping.Names().VLANs() {
		named[ref] = name
	}
	sw1 := netip.MustParseAddr("192.0.2.1")
	if _, carried := named[VLANRef{sw1, 30}]; carried {
		t.Error("VLANs() carried the unnamed VLAN, want no naming row for it")
	}
	if got := named[VLANRef{sw1, 20}]; got != "servers" {
		t.Errorf("VLANs()[20] = %q, want servers", got)
	}
	if len(named) != 3 {
		t.Errorf("VLANs() carried %d rows, want the three the file names", len(named))
	}
}

// TestVLAN_SharesOneTableThroughAnAnchor pins the spelling the file format
// documents rather than the lookup: one L2 domain reaches several devices,
// and repeating its prefixes per device is where the copies drift apart. The
// alias is the yaml library's to expand, so what this holds is that the form
// the examples teach keeps reaching every device that refers to it.
func TestVLAN_SharesOneTableThroughAnAnchor(t *testing.T) {
	t.Parallel()

	const document = `devices:
  192.0.2.1:
    vlans: &site
      10:
        name: campus
        prefixes: [10.0.0.0/8]
  192.0.2.2:
    vlans: *site
`

	v := NewVLAN(loadMapping(t, document))
	for _, exporter := range []string{"192.0.2.1", "192.0.2.2"} {
		if got := enrichBetween(v, exporter, "10.0.0.7", "203.0.113.7"); got.SrcVLAN != 10 {
			t.Errorf("SrcVLAN on %s = %d, want 10", exporter, got.SrcVLAN)
		}
	}
}

// TestVLAN_RefusesAnUnusableDocument covers every spelling the loader turns
// away. Each fails the whole file rather than the entry, so a reload keeps
// the table already in force instead of publishing a partial one.
func TestVLAN_RefusesAnUnusableDocument(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
	}{
		{"a VLAN of zero", "devices:\n  192.0.2.1:\n    vlans:\n      0:\n        prefixes: [10.0.0.0/8]\n"},
		{"a VLAN past 4094", "devices:\n  192.0.2.1:\n    vlans:\n      4095:\n        prefixes: [10.0.0.0/8]\n"},
		{
			name:     "a VLAN with a leading zero",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      \"010\":\n        prefixes: [10.0.0.0/8]\n",
		},
		{
			name:     "a VLAN that is not a number",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      campus:\n        prefixes: [10.0.0.0/8]\n",
		},
		{"a VLAN naming no prefix", "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        name: campus\n"},
		{"an empty prefix list", "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: []\n"},
		{
			name:     "a prefix that is an address",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: [10.0.0.1]\n",
		},
		{
			name:     "a prefix carrying host bits",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: [10.0.0.1/24]\n",
		},
		{
			name:     "the default route",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: [0.0.0.0/0]\n",
		},
		{
			name:     "the IPv6 default route",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: [\"::/0\"]\n",
		},
		{
			name:     "an IPv4-mapped prefix",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: [\"::ffff:10.0.0.0/104\"]\n",
		},
		{
			name: "one prefix on two VLANs of one device",
			document: "devices:\n  192.0.2.1:\n    vlans:\n" +
				"      10:\n        prefixes: [10.0.0.0/8]\n      20:\n        prefixes: [10.0.0.0/8]\n",
		},
		{
			name: "a prefix listed twice under one VLAN",
			document: "devices:\n  192.0.2.1:\n    vlans:\n" +
				"      10:\n        prefixes: [10.0.0.0/8, 10.0.0.0/8]\n",
		},
		{
			name:     "a blank VLAN name",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        name: \"  \"\n        prefixes: [10.0.0.0/8]\n",
		},
		{
			// The prefixes are usable, so only the strict decode can refuse
			// this: without one the entry fails for naming no prefix and the
			// case would pass whether unknown keys were refused or not.
			name: "an unknown key beside the VLANs",
			document: "devices:\n  192.0.2.1:\n    vlans:\n      10:\n" +
				"        prefixes: [10.0.0.0/8]\n        subnet: [10.0.0.0/8]\n",
		},
		{"a device whose VLANs are empty", "devices:\n  192.0.2.1:\n    vlans: {}\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewMapping(writeMapping(t, tt.document)); err == nil {
				t.Error("NewMapping() error = nil, want the document refused")
			}
		})
	}
}

// TestVLAN_AcceptsOneVLANAsTheWholeDeviceEntry pins that a device may carry
// VLANs without a hostname or an interface, the three being independent
// things one file happens to hold.
func TestVLAN_AcceptsOneVLANAsTheWholeDeviceEntry(t *testing.T) {
	t.Parallel()

	const document = "devices:\n  192.0.2.1:\n    vlans:\n      10:\n        prefixes: [10.0.0.0/8]\n"

	v := NewVLAN(loadMapping(t, document))
	if got := enrichBetween(v, "192.0.2.1", "10.0.0.7", "203.0.113.7"); got.SrcVLAN != 10 {
		t.Errorf("SrcVLAN = %d, want 10", got.SrcVLAN)
	}
}

// BenchmarkVLAN_Enrich measures the decode-path cost of the lookup, which is
// two roundings per distinct prefix length the device declares.
func BenchmarkVLAN_Enrich(b *testing.B) {
	path := filepath.Join(b.TempDir(), "mapping.yml")
	if err := os.WriteFile(path, []byte(fixtureVLANs), 0o600); err != nil {
		b.Fatalf("writing the mapping file: %v", err)
	}
	mapping, err := NewMapping(path)
	if err != nil {
		b.Fatalf("NewMapping() error = %v", err)
	}
	v := NewVLAN(mapping)

	records := []flow.Record{
		{ // both sides local, resolving at the narrowest length held
			Exporter: netip.MustParseAddr("192.0.2.1"),
			SrcAddr:  netip.MustParseAddr("10.1.1.7"),
			DstAddr:  netip.MustParseAddr("10.1.1.8"),
		},
		{ // one side local, the other walking every length to a miss
			Exporter: netip.MustParseAddr("192.0.2.1"),
			SrcAddr:  netip.MustParseAddr("10.2.0.7"),
			DstAddr:  netip.MustParseAddr("203.0.113.7"),
		},
		{ // neither side local, which is every length walked twice
			Exporter: netip.MustParseAddr("192.0.2.1"),
			SrcAddr:  netip.MustParseAddr("198.51.100.7"),
			DstAddr:  netip.MustParseAddr("203.0.113.7"),
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		r := records[i%len(records)]
		v.Enrich(&r)
	}
}
