// Package decoder turns received datagrams into normalized flow records.
// This file parses the sampled packet headers sFlow ships: Ethernet with
// optional VLAN tags, then IPv4 or IPv6, then the transport ports. A header
// cut short mid-layer keeps what decoded and leaves the rest absent.
package decoder

import (
	"encoding/binary"
	"net/netip"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// EtherTypes and protocol numbers the header walk understands.
const (
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86DD
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88A8
	protocolTCP    = 6
	protocolUDP    = 17
	ethernetHdrLen = 14
	vlanTagLen     = 4
	ipv4MinHdrLen  = 20
	ipv6HdrLen     = 40
	transportPorts = 4
	tcpFlagsOffset = 13
)

// readIPPacket walks a sampled section that starts at the IP header, the
// version nibble selecting the family. A section that is neither decodes to
// nothing, which is absence rather than a guess.
func readIPPacket(packet []byte, r *flow.Record) {
	if len(packet) == 0 {
		return
	}

	switch packet[0] >> 4 {
	case 4:
		readIPv4Header(packet, r)
	case 6:
		readIPv6Header(packet, r)
	}
}

// readEthernetFrame walks one sampled frame into the record. It reports
// false only when not even the Ethernet header fits: a frame that decodes
// down to IP without ports is still a flow reading.
func readEthernetFrame(frame []byte, r *flow.Record) bool {
	if len(frame) < ethernetHdrLen {
		return false
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[ethernetHdrLen:]

	// Walk VLAN stacking: each tag pushes the real EtherType four bytes on.
	for etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		if len(payload) < vlanTagLen {
			return true
		}
		etherType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[vlanTagLen:]
	}

	switch etherType {
	case etherTypeIPv4:
		readIPv4Header(payload, r)
	case etherTypeIPv6:
		readIPv6Header(payload, r)
	}
	return true
}

// readIPv4Header reads the sampled IPv4 header and its transport ports.
func readIPv4Header(packet []byte, r *flow.Record) {
	if len(packet) < ipv4MinHdrLen {
		return
	}

	headerLen := int(packet[0]&0x0F) * 4
	if headerLen < ipv4MinHdrLen || headerLen > len(packet) {
		return
	}

	r.TOS = packet[1]
	r.Protocol = packet[9]
	r.SrcAddr = netip.AddrFrom4([4]byte(packet[12:16]))
	r.DstAddr = netip.AddrFrom4([4]byte(packet[16:20]))

	readTransport(packet[headerLen:], r)
}

// readIPv6Header reads the sampled IPv6 header. Extension headers are not
// walked: the ports stay absent rather than misread from an extension.
func readIPv6Header(packet []byte, r *flow.Record) {
	if len(packet) < ipv6HdrLen {
		return
	}

	r.TOS = packet[0]<<4 | packet[1]>>4
	r.Protocol = packet[6]
	r.SrcAddr = addrFrom16([16]byte(packet[8:24]))
	r.DstAddr = addrFrom16([16]byte(packet[24:40]))

	readTransport(packet[ipv6HdrLen:], r)
}

// readTransport reads the ports, and the flags for TCP, where the sampled
// header still covers them.
func readTransport(segment []byte, r *flow.Record) {
	switch r.Protocol {
	case protocolTCP:
		if len(segment) < transportPorts {
			return
		}
		r.SrcPort = binary.BigEndian.Uint16(segment[0:2])
		r.DstPort = binary.BigEndian.Uint16(segment[2:4])
		if len(segment) > tcpFlagsOffset {
			r.TCPFlags = segment[tcpFlagsOffset]
		}
	case protocolUDP:
		if len(segment) < transportPorts {
			return
		}
		r.SrcPort = binary.BigEndian.Uint16(segment[0:2])
		r.DstPort = binary.BigEndian.Uint16(segment[2:4])
	}
}
