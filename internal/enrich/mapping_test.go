package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// writeMapping puts one document on disk and returns its path.
func writeMapping(t *testing.T, document string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "mapping.yml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}
	return path
}

// loadMapping loads one document, failing the test if it does not load.
func loadMapping(t *testing.T, document string) *Mapping {
	t.Helper()

	m, err := NewMapping(writeMapping(t, document))
	if err != nil {
		t.Fatalf("NewMapping() error = %v, want nil", err)
	}
	return m
}

const fixtureMapping = `devices:
  192.0.2.1:
    hostname: sw1.example.net
    interfaces:
      10102: Gi0/2
      10110: Gi0/10
  ::ffff:192.0.2.2:
    interfaces:
      1: Vl1
services:
  5246/udp: capwap-control
  179/tcp: bgp
`

func TestMapping_ParsesDevicesInterfacesAndServices(t *testing.T) {
	t.Parallel()

	names := loadMapping(t, fixtureMapping).Names()

	devices := map[netip.Addr]string{}
	for exporter, hostname := range names.Devices() {
		devices[exporter] = hostname
	}
	// The second device names no hostname, so it carries no naming row.
	if len(devices) != 1 || devices[netip.MustParseAddr("192.0.2.1")] != "sw1.example.net" {
		t.Errorf("Devices() = %v, want the one device the file names", devices)
	}

	for _, tt := range []struct {
		exporter string
		ifIndex  uint32
		want     string
	}{
		{"192.0.2.1", 10102, "Gi0/2"},
		{"192.0.2.1", 10110, "Gi0/10"},
		// The receiver unmaps every source address, so the mapped spelling
		// has to reach the same key a record does.
		{"192.0.2.2", 1, "Vl1"},
	} {
		got, ok := names.Interface(netip.MustParseAddr(tt.exporter), tt.ifIndex)
		if !ok || got != tt.want {
			t.Errorf("Interface(%s, %d) = %q, %v; want %q, true", tt.exporter, tt.ifIndex, got, ok, tt.want)
		}
	}
	if _, ok := names.Interface(netip.MustParseAddr("192.0.2.1"), 9); ok {
		t.Error("Interface() answered for an ifIndex the file does not name, want no row")
	}
}

// TestMapping_RefusesADocumentItCannotTrust covers every rejection, each of
// which fails the whole load: a file with one bad line publishing the rest
// would name some ports and silently drop others.
func TestMapping_RefusesADocumentItCannotTrust(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
	}{
		{"an unknown key", "devices:\n  192.0.2.1:\n    host: sw1\n"},
		{"a top-level unknown key", "device:\n  192.0.2.1:\n    hostname: sw1\n"},
		{"a key that is not an address", "devices:\n  sw1.example.net:\n    hostname: sw1\n"},
		{"an ifIndex of zero", "devices:\n  192.0.2.1:\n    interfaces:\n      0: Gi0/1\n"},
		{"an ifIndex past Integer32", "devices:\n  192.0.2.1:\n    interfaces:\n      2147483648: Gi0/1\n"},
		{"an ifIndex with a leading zero", "devices:\n  192.0.2.1:\n    interfaces:\n      \"010\": Gi0/1\n"},
		{"an ifIndex that is not a number", "devices:\n  192.0.2.1:\n    interfaces:\n      Gi0/1: Gi0/1\n"},
		{"a device naming nothing", "devices:\n  192.0.2.1: {}\n"},
		{"a device whose interfaces are empty", "devices:\n  192.0.2.1:\n    interfaces: {}\n"},
		{"a null interface name", "devices:\n  192.0.2.1:\n    interfaces:\n      2: ~\n"},
		{"a blank hostname", "devices:\n  192.0.2.1:\n    hostname: \"   \"\n"},
		{"a no-break space hostname", "devices:\n  192.0.2.1:\n    hostname: \"\u00a0\"\n"},
		{"an ideographic space hostname", "devices:\n  192.0.2.1:\n    hostname: \"\u3000\"\n"},
		{"a tab hostname", "devices:\n  192.0.2.1:\n    hostname: \"\\t\"\n"},
		{"a zero-width space in a hostname", "devices:\n  192.0.2.1:\n    hostname: \"sw\u200b1\"\n"},
		{"an over-long hostname", "devices:\n  192.0.2.1:\n    hostname: " + strings.Repeat("a", 256) + "\n"},
		{"a service key with no transport", "services:\n  5246: capwap\n"},
		{"a service on an unknown transport", "services:\n  5246/sctp: capwap\n"},
		{"a port past 65535", "services:\n  65536/udp: capwap\n"},
		{"a port of zero", "services:\n  0/udp: capwap\n"},
		{"a port with a leading zero", "services:\n  \"0179/tcp\": bgp\n"},
		{"a duplicate key", "devices:\n  192.0.2.1:\n    hostname: a\n  192.0.2.1:\n    hostname: b\n"},
		{"a second document", fixtureMapping + "---\n"},
		{"an empty file", ""},
		{"comments alone", "# nothing here\n"},
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

// TestMapping_RefusesTwoSpellingsOfOneAddress covers the duplicate yaml
// cannot see: its own check compares the keys as written, where these three
// pairs are one address each once parsed.
func TestMapping_RefusesTwoSpellingsOfOneAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
	}{
		{"mapped and bare v4", "devices:\n  192.0.2.1:\n    hostname: a\n  ::ffff:192.0.2.1:\n    hostname: b\n"},
		{"upper and lower case", "devices:\n  2001:DB8::1:\n    hostname: a\n  2001:db8::1:\n    hostname: b\n"},
		{
			name: "compressed and expanded",
			document: "devices:\n  2001:db8::1:\n    hostname: a\n" +
				"  2001:db8:0:0:0:0:0:1:\n    hostname: b\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewMapping(writeMapping(t, tt.document)); err == nil {
				t.Error("NewMapping() error = nil, want the duplicate address refused")
			}
		})
	}
}

// TestMapping_AcceptsADocumentThatNamesNothing pins the one empty form that
// loads. A file the operator has emptied on purpose is how names are taken
// away at reload, where an empty file is a truncated write.
func TestMapping_AcceptsADocumentThatNamesNothing(t *testing.T) {
	t.Parallel()

	names := loadMapping(t, "devices: {}\n").Names()
	for exporter := range names.Devices() {
		t.Errorf("Devices() answered %s, want nothing named", exporter)
	}
}

// TestMapping_ReloadKeepsTheSetItCannotReplace pins the rule every source
// here shares: a load that fails leaves the previous names in force, so a
// file caught half-written never unnames a fleet.
func TestMapping_ReloadKeepsTheSetItCannotReplace(t *testing.T) {
	t.Parallel()

	path := writeMapping(t, fixtureMapping)
	m, err := NewMapping(path)
	if err != nil {
		t.Fatalf("NewMapping() error = %v, want nil", err)
	}

	if err := os.WriteFile(path, []byte("devices:\n  not-an-address:\n    hostname: a\n"), 0o600); err != nil {
		t.Fatalf("rewriting the mapping file: %v", err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("Reload() error = nil, want the broken document refused")
	}

	if got, ok := m.Names().Interface(netip.MustParseAddr("192.0.2.1"), 10102); !ok || got != "Gi0/2" {
		t.Errorf("Interface() = %q, %v after a failed reload; want the previous set kept", got, ok)
	}
}

// TestMapping_NamesFromTheOperatorsOwnPorts covers both directions and the
// order between them, which is the destination first: it is the service side
// of a conversation as exported.
func TestMapping_NamesFromTheOperatorsOwnPorts(t *testing.T) {
	t.Parallel()

	const document = "services:\n  5246/udp: capwap-control\n  5247/udp: capwap-data\n"

	tests := []struct {
		name             string
		srcPort, dstPort uint16
		want             string
	}{
		{"the destination port", 51234, 5246, "capwap-control"},
		{"the source port", 5247, 51234, "capwap-data"},
		{"both ports named, destination first", 5247, 5246, "capwap-control"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := loadMapping(t, document)
			r := serviceRecord(protocolUDP, tt.srcPort, tt.dstPort)
			m.Enrich(&r)

			if r.AppName != tt.want {
				t.Errorf("AppName = %q, want %q", r.AppName, tt.want)
			}
			if got := m.Snapshot(); got.Filled != 1 {
				t.Errorf("Snapshot() = %+v, want one filled", got)
			}
		})
	}
}

// TestMapping_LeavesTheDevicesOwnReadingAlone is the regression test for a
// port table overwriting what the device measured. A device running AVC or
// App-ID read the application off the packet where this table knows only a
// number, so a port name replacing it would publish a worse answer under the
// same label -- and, on a record carrying only IE 95, would replace a
// numbered identifier no port table can improve on.
func TestMapping_LeavesTheDevicesOwnReadingAlone(t *testing.T) {
	t.Parallel()

	const document = "services:\n  443/tcp: operator-https\n"

	tests := []struct {
		name    string
		prepare func(*flow.Record)
		want    string
	}{
		{"the device named it", func(r *flow.Record) { r.AppName = "ms-teams" }, "ms-teams"},
		{"the device numbered it", func(r *flow.Record) { r.AppID = 0x0D_00_0C }, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := loadMapping(t, document)
			r := serviceRecord(protocolTCP, 51234, 443)
			tt.prepare(&r)
			m.Enrich(&r)

			if r.AppName != tt.want {
				t.Errorf("AppName = %q, want %q left as the device reported it", r.AppName, tt.want)
			}
			// The count is what separates leaving the record alone from
			// looking it up and finding nothing.
			if got := m.Snapshot(); got.Skipped != 1 || got.Filled != 0 {
				t.Errorf("Snapshot() = %+v, want one skipped and nothing filled", got)
			}
		})
	}
}

// TestMapping_UnknownPortsAreCounted pins that a record neither port of which
// the file names leaves no name and is counted as unknown, which is what the
// coverage ratio divides by.
func TestMapping_UnknownPortsAreCounted(t *testing.T) {
	t.Parallel()

	m := loadMapping(t, "services:\n  5246/udp: capwap-control\n")
	r := serviceRecord(protocolTCP, 51234, 443)
	m.Enrich(&r)

	if r.AppName != "" {
		t.Errorf("AppName = %q, want no name from a port the file does not carry", r.AppName)
	}
	if got := m.Snapshot(); got.Unknown != 1 || got.Filled != 0 {
		t.Errorf("Snapshot() = %+v, want one unknown", got)
	}
}
