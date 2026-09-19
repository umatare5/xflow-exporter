// This file names an application from the transport port.

package enrich

import (
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// servicePort keys the table. IANA assigns per protocol, and a few numbers
// carry different services on TCP and UDP, so the protocol is part of the key
// rather than assumed.
type servicePort struct {
	protocol uint8
	port     uint16
}

// The transport protocols the table covers.
const (
	protocolTCP = 6
	protocolUDP = 17
)

// serviceNetBIOS spans three consecutive numbers, which is why it is the one
// name in the table below written once rather than per port.
const serviceNetBIOS = "netbios"

// serviceTableSize is the table's capacity hint: a number registered under
// both transports holds two entries, a single-transport one holds one.
const serviceTableSize = 86

// tcpudp registers one name under both transports, which is how IANA assigns
// the overwhelming majority of these.
func tcpudp(port uint16, name string, table map[servicePort]string) {
	table[servicePort{protocolTCP, port}] = name
	table[servicePort{protocolUDP, port}] = name
}

// tcpOnly registers a name under TCP alone, for a service the other transport
// never carries: registering it under both would name a flow that merely
// reused the number as an ephemeral port.
func tcpOnly(port uint16, name string, table map[servicePort]string) {
	table[servicePort{protocolTCP, port}] = name
}

// udpOnly is tcpOnly's counterpart.
func udpOnly(port uint16, name string, table map[servicePort]string) {
	table[servicePort{protocolUDP, port}] = name
}

// serviceNames maps a port to the application conventionally reached there.
//
// The table is deliberately short. It carries the services an operator reads
// a traffic breakdown for, not the several thousand numbers IANA has on
// record: a name nobody recognizes adds a label value without adding meaning,
// and a wrong guess is worse than the number it replaced. A number one product
// conventionally uses is a mapping file's entry rather than one of these.
var serviceNames = buildServiceNames()

func buildServiceNames() map[servicePort]string {
	table := make(map[servicePort]string, serviceTableSize)

	// A well-known client port is absent where the server port already names
	// the exchange in both directions: Enrich falls back to the source port,
	// so DHCP's 68 and DHCPv6's 546 would name nothing 67 and 547 do not.
	for port, name := range map[uint16]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		67:    "dhcp",
		69:    "tftp",
		80:    "http",
		88:    "kerberos",
		123:   "ntp",
		135:   "msrpc",
		137:   serviceNetBIOS,
		138:   serviceNetBIOS,
		139:   serviceNetBIOS,
		161:   "snmp",
		162:   "snmp-trap",
		179:   "bgp",
		389:   "ldap",
		445:   "smb",
		514:   "syslog",
		547:   "dhcpv6",
		587:   "submission",
		636:   "ldaps",
		993:   "imaps",
		1433:  "mssql",
		1812:  "radius",
		1813:  "radius-acct",
		2049:  "nfs",
		3128:  "http-proxy",
		3306:  "mysql",
		3389:  "rdp",
		4500:  "ipsec-nat-t",
		5060:  "sip",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-alt",
		8443:  "https-alt",
		27017: "mongodb",
	} {
		tcpudp(port, name, table)
	}

	// RadSec, and the two numbers whose UDP side below carries a different
	// protocol rather than the same one over datagrams.
	for port, name := range map[uint16]string{
		443:  "https",
		853:  "dns-over-tls",
		2083: "radsec",
	} {
		tcpOnly(port, name, table)
	}

	// The tunnels, the flow protocols, and the QUIC-borne successors to two
	// of the TCP services above.
	for port, name := range map[uint16]string{
		443:  "http3",
		500:  "isakmp",
		853:  "dns-over-quic",
		2055: "netflow",
		4739: "ipfix",
		4789: "vxlan",
		6343: "sflow",
	} {
		udpOnly(port, name, table)
	}

	return table
}

// Services names an application from the transport ports of a record.
type Services struct {
	counters
}

// serviceBits marks every port the built-in table names, one bit per port
// per transport. The aggregation asks this of both ports of every record, so
// it is a bitmap rather than the map the naming path reads: 16 KiB of fixed
// state answers in a couple of nanoseconds where the map takes closer to
// twenty.
var serviceBits = buildServiceBits()

// serviceBitsWords is 65536 ports over 64 bits a word.
const serviceBitsWords = 1 << 16 / 64

func buildServiceBits() [2][serviceBitsWords]uint64 {
	var bits [2][serviceBitsWords]uint64
	for key := range serviceNames {
		if i, ok := serviceTransport(key.protocol); ok {
			bits[i][key.port>>6] |= 1 << (key.port & 63)
		}
	}
	return bits
}

// serviceTransport indexes the two transports the table covers. IANA assigns
// per protocol, and nothing else carries a port this exporter reads.
func serviceTransport(protocol uint8) (int, bool) {
	switch protocol {
	case protocolTCP:
		return 0, true
	case protocolUDP:
		return 1, true
	default:
		return 0, false
	}
}

// IsService reports whether the built-in table names a service at that port.
// It answers what the aggregation asks of a conversation -- which of its two
// ports is the service side -- rather than what the name is.
func IsService(protocol uint8, port uint16) bool {
	i, ok := serviceTransport(protocol)
	return ok && serviceBits[i][port>>6]&(1<<(port&63)) != 0
}

// NewServices creates the port-based application enricher.
func NewServices() *Services {
	return &Services{}
}

// Name implements Enricher.
func (s *Services) Name() string {
	return "services"
}

// Snapshot implements Enricher.
func (s *Services) Snapshot() Snapshot {
	return s.snapshot(s.Name())
}

// Enrich names the application from the port, and leaves the record alone
// when the device already named it.
//
// The destination port is tried first, being the service side of a
// conversation as exported. The source port is tried next, because a device
// exporting the return direction reports the service there instead. A record
// naming neither keeps no name at all: the ephemeral port of a client tells
// nothing about the application.
func (s *Services) Enrich(r *flow.Record) {
	if r.AppName != "" || r.AppID != 0 {
		s.skipped.Add(1)
		return
	}

	if name, ok := serviceNames[servicePort{r.Protocol, r.DstPort}]; ok {
		r.AppName = name
		s.filled.Add(1)
		return
	}
	if name, ok := serviceNames[servicePort{r.Protocol, r.SrcPort}]; ok {
		r.AppName = name
		s.filled.Add(1)
		return
	}

	s.unknown.Add(1)
}
