//go:build linux

package receiver

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/ipv4"
)

// datagramReader reads datagrams from one socket. The Linux implementation
// reads a whole batch per recvmmsg round trip.
type datagramReader struct {
	pc   *ipv4.PacketConn
	msgs []ipv4.Message
	take func() []byte
}

// newDatagramReader wraps conn for batch reads. The ipv4 wrapper is a
// misnomer here: recvmmsg operates on the file descriptor, so a dual-stack
// socket delivers IPv6 peers through it unchanged. put is unused: a failed
// batch read keeps its buffers parked in msgs for the next call.
func newDatagramReader(conn *net.UDPConn, take func() []byte, _ func([]byte)) *datagramReader {
	return &datagramReader{pc: ipv4.NewPacketConn(conn), take: take}
}

// read fills out with up to len(out) datagrams from one recvmmsg call and
// reports how many arrived. Each returned datagram owns its pooled buffer.
func (r *datagramReader) read(out []rawDatagram) (int, error) {
	if r.msgs == nil {
		r.msgs = make([]ipv4.Message, len(out))
	}
	for i := range r.msgs {
		if r.msgs[i].Buffers == nil {
			r.msgs[i].Buffers = [][]byte{r.take()}
		}
	}

	count, err := r.pc.ReadBatch(r.msgs, 0)
	if err != nil {
		return 0, err
	}

	for i := range count {
		msg := &r.msgs[i]
		out[i] = rawDatagram{
			buf:       msg.Buffers[0],
			length:    msg.N,
			src:       udpAddrPort(msg.Addr),
			truncated: msg.Flags&syscall.MSG_TRUNC != 0,
		}
		// Ownership of the buffer moved into out, so the slot refills from the
		// pool on the next read.
		msg.Buffers = nil
	}

	return count, nil
}

// udpAddrPort converts the batch message address, tolerating the nil a raw
// socket error path can leave.
func udpAddrPort(addr net.Addr) netip.AddrPort {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	return udpAddr.AddrPort()
}
