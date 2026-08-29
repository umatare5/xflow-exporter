package collector

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/decoder"
)

// buildV5 crafts a minimal one-record NetFlow v5 datagram for driving the
// decoder the collector under test reads.
func buildV5() []byte {
	payload := make([]byte, 24+48)
	payload[1] = 5  // version
	payload[3] = 1  // count
	payload[9] = 1  // unix_secs, any non-zero epoch
	payload[62] = 6 // protocol
	return payload
}

func TestDecoderCollector_Describe(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(decoder.New())

	ch := make(chan *prometheus.Desc, 8)
	go func() {
		defer close(ch)
		c.Describe(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	if count != 3 {
		t.Errorf("Describe() emitted %d descriptors, want 3", count)
	}
}

func TestDecoderCollector_EmptyUntilTraffic(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(decoder.New())

	if got := testutil.CollectAndCount(c); got != 0 {
		t.Errorf("CollectAndCount() = %d series before any datagram, want 0", got)
	}
}

func TestDecoderCollector_ReportsOutcomes(t *testing.T) {
	t.Parallel()

	d := decoder.New()
	exporter := netip.MustParseAddr("192.0.2.10")

	if _, err := d.Decode(exporter, buildV5(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if _, err := d.Decode(exporter, []byte{0x00, 0x07, 0x00, 0x00}, nil); err == nil {
		t.Fatal("Decode() error = nil, want an unsupported version rejection")
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_decode_errors_total Datagrams rejected per exporter, version and reason since process start
# TYPE xflow_decode_errors_total counter
xflow_decode_errors_total{exporter="192.0.2.10",reason="unsupported_version",version="unknown"} 1
# HELP xflow_flows_total Flow records decoded per exporter and version since process start
# TYPE xflow_flows_total counter
xflow_flows_total{exporter="192.0.2.10",version="netflow_v5"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_flows_total", "xflow_decode_errors_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}

	// The freshness gauge exists exactly once a decode has succeeded.
	if got := testutil.CollectAndCount(c, "xflow_last_flow_timestamp_seconds"); got != 1 {
		t.Errorf("last flow timestamp series = %d, want 1", got)
	}
}

func TestCollector_RegisterDecoderCollector(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterDecoderCollector(decoder.New())

	// The registry accepts the collector; series appear with traffic.
	if _, err := c.Registry().Gather(); err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
}
