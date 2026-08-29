//go:build !linux

package receiver

import (
	"net"
)

// datagramReader reads datagrams from one socket. Platforms without recvmmsg
// read one datagram per call, so a batch degenerates to a single read.
type datagramReader struct {
	conn *net.UDPConn
	take func() []byte
	put  func([]byte)
}

// newDatagramReader wraps conn for single-datagram reads.
func newDatagramReader(conn *net.UDPConn, take func() []byte, put func([]byte)) *datagramReader {
	return &datagramReader{conn: conn, take: take, put: put}
}

// read fills out[0] with one datagram and reports one. Without recvmsg flags
// the kernel truncates silently, so a payload filling the whole buffer is
// treated as truncated: a legitimate datagram of exactly that size is
// indistinguishable from a longer one that was cut.
func (r *datagramReader) read(out []rawDatagram) (int, error) {
	buf := r.take()

	length, src, err := r.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		r.put(buf)
		return 0, err
	}

	out[0] = rawDatagram{
		buf:       buf,
		length:    length,
		src:       src,
		truncated: length == len(buf),
	}
	return 1, nil
}
