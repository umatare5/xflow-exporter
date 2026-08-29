// Package receiver provides the UDP listeners flow datagrams arrive on.
package receiver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/pool"
)

// Packet is one received datagram. Data aliases a pooled buffer, so the
// consumer must hand the packet back through Release once decoded.
type Packet struct {
	Data     []byte
	Src      netip.AddrPort
	Listener string
}

// rawDatagram is what a platform reader hands the read loop: the pooled buffer,
// the payload length, the source, and whether the kernel truncated the payload.
type rawDatagram struct {
	buf       []byte
	length    int
	src       netip.AddrPort
	truncated bool
}

// Receiver owns the UDP sockets, the read loops and the bounded queue between
// them and the decoders. Listen binds, Serve reads until the context ends, and
// neither read loop ever blocks on a slow consumer: a full queue drops the
// datagram and counts it instead.
type Receiver struct {
	cfg   config.Receiver
	stats *Stats
	bufs  *pool.Pool[[]byte]
	queue chan Packet
	conns []*net.UDPConn
}

// New creates a receiver for the given configuration.
func New(cfg config.Receiver) *Receiver {
	size := cfg.MaxPacketSize
	return &Receiver{
		cfg:   cfg,
		stats: newStats(cfg),
		bufs:  pool.New(func() []byte { return make([]byte, size) }),
		queue: make(chan Packet, cfg.QueueSize),
	}
}

// Stats returns the receiver statistics for the metrics collector.
func (r *Receiver) Stats() *Stats {
	return r.stats
}

// Packets returns the queue the read loops feed. It is closed when Serve
// returns, which is what ends the consumer.
func (r *Receiver) Packets() <-chan Packet {
	return r.queue
}

// Release returns a packet's buffer to the pool. Every packet taken from
// Packets must be released exactly once, and its Data not touched after.
func (r *Receiver) Release(p Packet) {
	r.bufs.Put(p.Data[:cap(p.Data)])
}

// Listen binds every configured address. It is separate from Serve so a bind
// failure surfaces synchronously at startup rather than inside a goroutine.
func (r *Receiver) Listen() error {
	for _, address := range r.cfg.Addresses {
		conn, err := listen(address, r.cfg.SockBufBytes)
		if err != nil {
			r.closeConns()
			return err
		}
		r.conns = append(r.conns, conn)
		slog.Info("Flow receiver listening", "listener", address)
	}
	return nil
}

// listen binds one UDP address and applies the socket buffer size.
func listen(address string, sockBufBytes int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolving receiver address %q: %w", address, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("binding receiver address %q: %w", address, err)
	}

	if sockBufBytes > 0 {
		// The kernel clamps the value to its own maximum, net.core.rmem_max on
		// Linux, and reports no error when it does, so failure here is limited
		// to a closed socket.
		if err := conn.SetReadBuffer(sockBufBytes); err != nil {
			closeConn(conn)
			return nil, fmt.Errorf("setting receive buffer on %q: %w", address, err)
		}
	}

	return conn, nil
}

// LocalAddrPorts reports the bound addresses, which a test binding port 0
// reads to learn the ports the kernel picked.
func (r *Receiver) LocalAddrPorts() []netip.AddrPort {
	addrs := make([]netip.AddrPort, 0, len(r.conns))
	for _, conn := range r.conns {
		udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			continue
		}
		addrs = append(addrs, udpAddr.AddrPort())
	}
	return addrs
}

// Serve runs one read loop per bound socket until ctx ends, then closes the
// sockets, waits for the loops, and closes the packet queue.
func (r *Receiver) Serve(ctx context.Context) {
	var wg sync.WaitGroup
	for i, conn := range r.conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.readLoop(conn, r.cfg.Addresses[i])
		}()
	}

	<-ctx.Done()
	r.closeConns()
	wg.Wait()
	close(r.queue)
}

// closeConns closes every bound socket, which unblocks the read loops.
func (r *Receiver) closeConns() {
	for _, conn := range r.conns {
		closeConn(conn)
	}
}

// closeConn closes one socket. A close failure changes nothing for the caller,
// so it is logged rather than returned.
func closeConn(conn *net.UDPConn) {
	if err := conn.Close(); err != nil {
		slog.Debug("Failed to close receiver socket", "error", err)
	}
}

// readLoop moves datagrams from one socket into the queue until the socket is
// closed under it.
func (r *Receiver) readLoop(conn *net.UDPConn, listener string) {
	ls := r.stats.Listener(listener)
	reader := newDatagramReader(conn, r.bufs.Get, r.bufs.Put)
	out := make([]rawDatagram, r.cfg.BatchSize)

	for {
		count, err := reader.read(out)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			ls.ReadErrors.Add(1)
			continue
		}

		for i := range count {
			r.enqueue(ls, listener, out[i])
		}
	}
}

// enqueue accounts one datagram and hands it to the queue, dropping rather
// than blocking when the queue is full.
func (r *Receiver) enqueue(ls *ListenerStats, listener string, d rawDatagram) {
	ls.Packets.Add(1)
	ls.Bytes.Add(uint64(d.length)) //nolint:gosec // A kernel-reported read length is never negative.

	// A truncated datagram cannot be decoded: the payload is cut mid-record
	// and the missing tail is unrecoverable.
	if d.truncated {
		ls.DroppedTruncated.Add(1)
		r.bufs.Put(d.buf)
		return
	}

	pkt := Packet{
		Data: d.buf[:d.length],
		// A dual-stack socket reports an IPv4 peer as an IPv4-mapped IPv6
		// address, and unmapping keeps one exporter to one spelling.
		Src:      netip.AddrPortFrom(d.src.Addr().Unmap(), d.src.Port()),
		Listener: listener,
	}

	select {
	case r.queue <- pkt:
	default:
		ls.DroppedQueueFull.Add(1)
		r.bufs.Put(d.buf)
	}
}

// QueueLength reports the datagrams waiting in the queue.
func (r *Receiver) QueueLength() int {
	return len(r.queue)
}

// QueueCapacity reports the queue bound.
func (r *Receiver) QueueCapacity() int {
	return cap(r.queue)
}
