package collector

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// testReceiver returns a receiver that never listens: the collector reads
// counters alone, and the tests drive them through Stats.
func testReceiver() *receiver.Receiver {
	return receiver.New(config.Receiver{
		Addresses:     []string{":2055", ":6343"},
		BatchSize:     config.DefaultReceiverBatchSize,
		QueueSize:     4,
		MaxPacketSize: config.DefaultReceiverMaxPacketSize,
	})
}

func TestReceiverCollector_Describe(t *testing.T) {
	t.Parallel()

	c := NewReceiverCollector(testReceiver())

	ch := make(chan *prometheus.Desc, 16)
	go func() {
		defer close(ch)
		c.Describe(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	if count != 6 {
		t.Errorf("Describe() emitted %d descriptors, want 6", count)
	}
}

func TestReceiverCollector_SeedsEverySeriesAtZero(t *testing.T) {
	t.Parallel()

	c := NewReceiverCollector(testReceiver())

	expected := `
# HELP xflow_receiver_dropped_packets_total Datagrams dropped before decoding per listener and reason since process start
# TYPE xflow_receiver_dropped_packets_total counter
xflow_receiver_dropped_packets_total{listener=":2055",reason="queue_full"} 0
xflow_receiver_dropped_packets_total{listener=":2055",reason="truncated"} 0
xflow_receiver_dropped_packets_total{listener=":6343",reason="queue_full"} 0
xflow_receiver_dropped_packets_total{listener=":6343",reason="truncated"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_receiver_dropped_packets_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestReceiverCollector_ReportsCounters(t *testing.T) {
	t.Parallel()

	r := testReceiver()
	ls := r.Stats().Listener(":2055")
	ls.Packets.Add(7)
	ls.Bytes.Add(900)
	ls.ReadErrors.Add(1)
	ls.DroppedQueueFull.Add(2)
	ls.DroppedTruncated.Add(3)

	c := NewReceiverCollector(r)

	expected := `
# HELP xflow_receiver_bytes_total Datagram payload bytes received per listener since process start
# TYPE xflow_receiver_bytes_total counter
xflow_receiver_bytes_total{listener=":2055"} 900
xflow_receiver_bytes_total{listener=":6343"} 0
# HELP xflow_receiver_dropped_packets_total Datagrams dropped before decoding per listener and reason since process start
# TYPE xflow_receiver_dropped_packets_total counter
xflow_receiver_dropped_packets_total{listener=":2055",reason="queue_full"} 2
xflow_receiver_dropped_packets_total{listener=":2055",reason="truncated"} 3
xflow_receiver_dropped_packets_total{listener=":6343",reason="queue_full"} 0
xflow_receiver_dropped_packets_total{listener=":6343",reason="truncated"} 0
# HELP xflow_receiver_packets_total Datagrams received per listener since process start, dropped ones included
# TYPE xflow_receiver_packets_total counter
xflow_receiver_packets_total{listener=":2055"} 7
xflow_receiver_packets_total{listener=":6343"} 0
# HELP xflow_receiver_queue_capacity Bound of the queue between the read loops and the decoders
# TYPE xflow_receiver_queue_capacity gauge
xflow_receiver_queue_capacity 4
# HELP xflow_receiver_queue_length Datagrams waiting between the read loops and the decoders
# TYPE xflow_receiver_queue_length gauge
xflow_receiver_queue_length 0
# HELP xflow_receiver_read_errors_total Socket read failures per listener since process start
# TYPE xflow_receiver_read_errors_total counter
xflow_receiver_read_errors_total{listener=":2055"} 1
xflow_receiver_read_errors_total{listener=":6343"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestCollector_RegisterReceiverCollector(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterReceiverCollector(testReceiver())

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	found := false
	for _, family := range families {
		if family.GetName() == "xflow_receiver_packets_total" {
			found = true
		}
	}
	if !found {
		t.Error("xflow_receiver_packets_total is absent, want the receiver collector registered")
	}
}
