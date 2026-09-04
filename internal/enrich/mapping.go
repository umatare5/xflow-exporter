// This file names devices and their interfaces from a file the operator
// maintains, and names an application from a port the built-in table misses.

package enrich

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// mappingLabelMax bounds one name. A label value longer than this says the
// file is not a mapping, and the bound is that assertion rather than a memory
// guard.
const mappingLabelMax = 255

// ifIndexMax is the upper bound RFC 2863 puts on InterfaceIndex, which it
// defines as a positive Integer32.
const ifIndexMax = 2_147_483_647

// mappingNumber is the spelling a numeric key must take. ParseUint reads a
// leading zero as decimal, so 010 and 10 would name one interface under two
// keys that yaml itself does not see as a duplicate.
var mappingNumber = regexp.MustCompile(`^[1-9]\d*$`)

// interfaceKey names one port of one device.
type interfaceKey struct {
	exporter netip.Addr
	ifIndex  uint32
}

// NameSet is one immutable snapshot of the mapping file. It is replaced
// wholesale on reload rather than mutated, so a lookup never sees a
// half-loaded set and never takes a lock.
type NameSet struct {
	devices    map[netip.Addr]string
	interfaces map[interfaceKey]string
	services   map[servicePort]string
}

// Devices reports every device the file names. The naming series built from
// it takes no cut, its bound being the file rather than the traffic.
func (s *NameSet) Devices() iter.Seq2[netip.Addr, string] {
	return maps.All(s.devices)
}

// Interface reports what the file calls one port of one device.
func (s *NameSet) Interface(exporter netip.Addr, ifIndex uint32) (string, bool) {
	name, ok := s.interfaces[interfaceKey{exporter, ifIndex}]
	return name, ok
}

// Mapping names devices, their interfaces and transport ports from one file
// this exporter reads from disk.
//
// Nothing is queried and nothing is sent. The file is written by whatever
// walks the devices, scripts/fetch-device-names.sh being one such, and a
// reload picks up what that left behind. That keeps SNMP off the decode path
// and out of this process entirely.
type Mapping struct {
	counters
	path string

	set atomic.Pointer[NameSet]
}

// NewMapping reads the file into the first snapshot. A file that cannot be
// read or parsed fails startup: an exporter naming nothing looks exactly like
// one whose file named nothing.
func NewMapping(path string) (*Mapping, error) {
	m := &Mapping{path: path}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Name implements Enricher.
func (m *Mapping) Name() string {
	return "mapping"
}

// Snapshot implements Enricher.
func (m *Mapping) Snapshot() Snapshot {
	return m.snapshot(m.Name())
}

// Names is the snapshot in force, which a scrape reads once.
func (m *Mapping) Names() *NameSet {
	return m.set.Load()
}

// Reload rebuilds the set from the file.
//
// The new set is built whole before it replaces the old one, so a file that
// has gone missing or been caught half-written leaves the previous names in
// place rather than unnaming every device at once.
func (m *Mapping) Reload() error {
	set, err := readMappingFile(m.path)
	if err != nil {
		return err
	}
	m.set.Store(set)
	return nil
}

// Enrich names the application from the operator's own port table.
//
// A record the device or an earlier source already named is left alone: the
// device saw the packet and read IE 95 or IE 96 off it, where this table
// knows only a port number. The destination port is tried first, being the
// service side of a conversation as exported.
func (m *Mapping) Enrich(r *flow.Record) {
	if r.AppName != "" || r.AppID != 0 {
		m.skipped.Add(1)
		return
	}

	set := m.set.Load()
	if set == nil {
		m.unknown.Add(1)
		return
	}

	if name, ok := set.services[servicePort{r.Protocol, r.DstPort}]; ok {
		r.AppName = name
		m.filled.Add(1)
		return
	}
	if name, ok := set.services[servicePort{r.Protocol, r.SrcPort}]; ok {
		r.AppName = name
		m.filled.Add(1)
		return
	}

	m.unknown.Add(1)
}

// mappingFile is the document as written. Numeric keys are read as strings so
// that the spelling reaches validation: yaml rejects a duplicate key and a
// type mismatch on its own, but a Go map takes whatever key decodes.
type mappingFile struct {
	Devices  map[string]mappingDevice `yaml:"devices"`
	Services map[string]string        `yaml:"services"`
}

// mappingDevice is one device's entry. A device carrying neither field names
// nothing, which is a typo rather than an intention.
type mappingDevice struct {
	Hostname   string            `yaml:"hostname"`
	Interfaces map[string]string `yaml:"interfaces"`
}

// readMappingFile parses one file into a snapshot.
func readMappingFile(path string) (*NameSet, error) {
	// The path is a flag the operator set, the same trust as the database
	// paths beside it. Nothing on the wire reaches it.
	file, err := os.Open(path) //nolint:gosec // The path is operator configuration.
	if err != nil {
		return nil, fmt.Errorf("opening the mapping file %q: %w", path, err)
	}
	defer closeMapping(file, path)

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	var doc mappingFile
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("reading the mapping file %q: %w", path, err)
	}

	// A second document is a file two writers appended to, of which only the
	// first would ever take effect. An empty file fails the decode above, so
	// a redirect truncated before its writer ran never empties the names.
	if err := decoder.Decode(new(mappingFile)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("the mapping file %q holds more than one document", path)
	}

	return buildNameSet(&doc)
}

// closeMapping releases the file. It has been read by then, so a close
// failure changes nothing for the caller.
func closeMapping(file *os.File, path string) {
	if err := file.Close(); err != nil {
		slog.Debug("Failed to close the mapping file", "path", path, "error", err)
	}
}

// buildNameSet validates the document and turns it into a snapshot. Every
// rejection fails the whole load, so a reload of a file with one bad line
// keeps the names already in force rather than publishing a partial set.
func buildNameSet(doc *mappingFile) (*NameSet, error) {
	set := &NameSet{
		devices:    make(map[netip.Addr]string, len(doc.Devices)),
		interfaces: make(map[interfaceKey]string),
		services:   make(map[servicePort]string, len(doc.Services)),
	}

	// Two spellings of one address are the one duplicate yaml cannot see:
	// Unmap folds ::ffff:192.0.2.1 onto 192.0.2.1, and case and zero
	// compression fold 2001:DB8::1 onto 2001:db8:0:0:0:0:0:1.
	seen := make(map[netip.Addr]struct{}, len(doc.Devices))
	for spelling, device := range doc.Devices {
		exporter, err := mappingAddr(spelling)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[exporter]; duplicate {
			return nil, fmt.Errorf("devices names %s twice, under two spellings of one address", exporter)
		}
		seen[exporter] = struct{}{}

		if err := addDevice(set, exporter, device); err != nil {
			return nil, err
		}
	}

	for spelling, name := range doc.Services {
		port, err := mappingService(spelling)
		if err != nil {
			return nil, err
		}
		if err := mappingValue(name); err != nil {
			return nil, fmt.Errorf("the name of service %q %w", spelling, err)
		}
		set.services[port] = name
	}

	return set, nil
}

// addDevice records one device's hostname and interface names.
func addDevice(set *NameSet, exporter netip.Addr, device mappingDevice) error {
	if device.Hostname == "" && len(device.Interfaces) == 0 {
		return fmt.Errorf("device %s names neither a hostname nor an interface", exporter)
	}

	if device.Hostname != "" {
		if err := mappingValue(device.Hostname); err != nil {
			return fmt.Errorf("the hostname of %s %w", exporter, err)
		}
		set.devices[exporter] = device.Hostname
	}

	for spelling, ifName := range device.Interfaces {
		ifIndex, err := mappingIfIndex(spelling)
		if err != nil {
			return fmt.Errorf("device %s: %w", exporter, err)
		}
		if err := mappingValue(ifName); err != nil {
			return fmt.Errorf("the name of %s interface %d %w", exporter, ifIndex, err)
		}
		set.interfaces[interfaceKey{exporter, ifIndex}] = ifName
	}
	return nil
}

// mappingAddr reads one devices key.
func mappingAddr(spelling string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(spelling)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("device %q is not an address: %w", spelling, err)
	}

	// Unmap because the receiver unmaps every source address: a file naming
	// ::ffff:192.0.2.1 means the device every record spells 192.0.2.1, and
	// netip holds the two as distinct keys.
	return addr.Unmap(), nil
}

// mappingIfIndex reads one interfaces key.
func mappingIfIndex(spelling string) (uint32, error) {
	if !mappingNumber.MatchString(spelling) {
		return 0, fmt.Errorf("interface %q is not a decimal number without a leading zero", spelling)
	}
	ifIndex, err := strconv.ParseUint(spelling, 10, 32)
	if err != nil || ifIndex > ifIndexMax {
		return 0, fmt.Errorf("interface %q is outside 1..%d", spelling, ifIndexMax)
	}
	return uint32(ifIndex), nil
}

// mappingService reads one services key, a port and a transport spelled
// port/proto. The transport is part of it because IANA assigns per protocol.
func mappingService(spelling string) (servicePort, error) {
	number, proto, cut := strings.Cut(spelling, "/")
	if !cut {
		return servicePort{}, fmt.Errorf("service %q is not spelled port/proto", spelling)
	}
	if !mappingNumber.MatchString(number) {
		return servicePort{}, fmt.Errorf("service %q names no decimal port without a leading zero", spelling)
	}
	port, err := strconv.ParseUint(number, 10, 16)
	if err != nil {
		return servicePort{}, fmt.Errorf("service %q is outside port 1..65535", spelling)
	}

	switch proto {
	case "tcp":
		return servicePort{protocolTCP, uint16(port)}, nil
	case "udp":
		return servicePort{protocolUDP, uint16(port)}, nil
	default:
		return servicePort{}, fmt.Errorf("service %q names neither tcp nor udp", spelling)
	}
}

// mappingValue checks one name for the label it becomes.
//
// unicode.IsPrint calls ASCII space printable, so the trim is what rejects a
// value of nothing but whitespace -- a label value no reader could tell from
// another -- and IsPrint what rejects an invisible mixed into a real name.
func mappingValue(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("is blank")
	}
	if len(value) > mappingLabelMax {
		return fmt.Errorf("is %d bytes, over the %d a name may take", len(value), mappingLabelMax)
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("carries %q, which is not printable", r)
		}
	}
	return nil
}
