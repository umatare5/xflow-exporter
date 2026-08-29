package receiver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// testReceiverConfig binds an ephemeral port so tests never collide. Port 0 is
// rejected by config.Validate on purpose, and these tests bypass Validate.
func testReceiverConfig() config.Receiver {
	return config.Receiver{
		Addresses:     []string{"127.0.0.1:0"},
		BatchSize:     config.DefaultReceiverBatchSize,
		QueueSize:     config.DefaultReceiverQueueSize,
		SockBufBytes:  config.DefaultReceiverSockBufBytes,
		MaxPacketSize: 1024,
	}
}

// startReceiver binds, serves, and returns the sender-side address.
func startReceiver(t *testing.T, cfg config.Receiver) (*Receiver, net.Addr, context.CancelFunc) {
	t.Helper()

	r := New(cfg)
	if err := r.Listen(); err != nil {
		t.Fatalf("Listen() error = %v, want nil", err)
	}

	addrs := r.LocalAddrPorts()
	if len(addrs) != len(cfg.Addresses) {
		t.Fatalf("LocalAddrPorts() returned %d addresses, want %d", len(addrs), len(cfg.Addresses))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return r, net.UDPAddrFromAddrPort(addrs[0]), cancel
}

// send writes one datagram to the receiver under test.
func send(t *testing.T, to net.Addr, payload []byte) {
	t.Helper()

	conn, err := net.Dial("udp", to.String())
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil", err)
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
}

// waitFor polls until check passes or the deadline expires.
func waitFor(t *testing.T, what string, check func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestReceiver_DeliversDatagrams(t *testing.T) {
	t.Parallel()

	r, addr, _ := startReceiver(t, testReceiverConfig())

	payloads := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	for _, payload := range payloads {
		send(t, addr, payload)
	}

	received := make(map[string]bool)
	for range payloads {
		select {
		case pkt := <-r.Packets():
			received[string(pkt.Data)] = true
			// The datagrams above were sent over IPv4, and enqueue unmaps the
			// source, so anything but a plain IPv4 address is a regression.
			if !pkt.Src.Addr().Is4() {
				t.Errorf("packet source %v is not an unmapped IPv4 address", pkt.Src)
			}
			if pkt.Listener != "127.0.0.1:0" {
				t.Errorf("packet listener = %q, want the configured address", pkt.Listener)
			}
			r.Release(pkt)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a packet")
		}
	}

	for _, payload := range payloads {
		if !received[string(payload)] {
			t.Errorf("payload %q was not delivered", payload)
		}
	}

	snap := r.Stats().Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot() returned %d listeners, want 1", len(snap))
	}
	if snap[0].Packets != 3 {
		t.Errorf("Packets = %d, want 3", snap[0].Packets)
	}
	if want := uint64(len("one") + len("two") + len("three")); snap[0].Bytes != want {
		t.Errorf("Bytes = %d, want %d", snap[0].Bytes, want)
	}
}

func TestReceiver_QueueFullDrops(t *testing.T) {
	t.Parallel()

	cfg := testReceiverConfig()
	cfg.QueueSize = 1

	r, addr, _ := startReceiver(t, cfg)

	// Nothing consumes the queue, so past the first datagram the rest must be
	// counted as dropped rather than blocking the read loop.
	for range 20 {
		send(t, addr, []byte("burst"))
	}

	waitFor(t, "a queue_full drop", func() bool {
		return r.Stats().Snapshot()[0].DroppedQueueFull > 0
	})

	if got := r.QueueLength(); got != 1 {
		t.Errorf("QueueLength() = %d, want the queue held at its bound of 1", got)
	}
	if got := r.QueueCapacity(); got != 1 {
		t.Errorf("QueueCapacity() = %d, want 1", got)
	}
}

func TestReceiver_TruncatedDatagramIsDropped(t *testing.T) {
	t.Parallel()

	cfg := testReceiverConfig()
	cfg.MaxPacketSize = 576

	r, addr, _ := startReceiver(t, cfg)

	send(t, addr, make([]byte, 1000))

	waitFor(t, "a truncated drop", func() bool {
		return r.Stats().Snapshot()[0].DroppedTruncated > 0
	})

	select {
	case pkt := <-r.Packets():
		t.Fatalf("a truncated datagram of %d bytes was delivered, want it dropped", len(pkt.Data))
	default:
	}
}

func TestReceiver_ServeClosesQueueOnCancel(t *testing.T) {
	t.Parallel()

	r, _, cancel := startReceiver(t, testReceiverConfig())

	cancel()

	select {
	case _, open := <-r.Packets():
		if open {
			t.Fatal("Packets() delivered a packet after cancel, want a closed channel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the queue to close")
	}
}

func TestReceiver_ListenFailsOnTakenPort(t *testing.T) {
	t.Parallel()

	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v, want nil", err)
	}
	defer occupied.Close()

	cfg := testReceiverConfig()
	cfg.Addresses = []string{occupied.LocalAddr().String()}

	r := New(cfg)
	if err := r.Listen(); err == nil {
		t.Error("Listen() error = nil, want a bind failure on the taken port")
	}
}

func TestReceiver_ListenFailsOnUnresolvableAddress(t *testing.T) {
	t.Parallel()

	cfg := testReceiverConfig()
	cfg.Addresses = []string{"not an address"}

	r := New(cfg)
	if err := r.Listen(); err == nil {
		t.Error("Listen() error = nil, want a resolution failure")
	}
}

func TestStats_SnapshotSeedsEveryListener(t *testing.T) {
	t.Parallel()

	cfg := testReceiverConfig()
	cfg.Addresses = []string{"127.0.0.1:0", "[::1]:0"}

	snap := New(cfg).Stats().Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot() returned %d listeners, want 2 seeded from configuration", len(snap))
	}
	for _, ls := range snap {
		if ls.Packets != 0 || ls.Bytes != 0 || ls.ReadErrors != 0 ||
			ls.DroppedQueueFull != 0 || ls.DroppedTruncated != 0 {
			t.Errorf("listener %s carries non-zero counters before any packet: %+v", ls.Listener, ls)
		}
	}
}
