package collector

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
)

// newTestDecoder builds a decoder with the default parser limits.
func newTestDecoder() *decoder.Decoder {
	return decoder.New(config.Parser{
		MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
		TemplateTTL:          config.DefaultParserTemplateTTL,
	})
}

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

	c := NewDecoderCollector(newTestDecoder())

	ch := make(chan *prometheus.Desc, 8)
	go func() {
		defer close(ch)
		c.Describe(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	if count != 7 {
		t.Errorf("Describe() emitted %d descriptors, want 7", count)
	}
}

func TestDecoderCollector_EmptyUntilTraffic(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(newTestDecoder())

	// Only the refusal counter, which is seeded so a first refusal reads as
	// a rise rather than as a new series. Nothing is published per exporter
	// until a datagram names one.
	if got := testutil.CollectAndCount(c); got != 1 {
		t.Errorf("CollectAndCount() = %d series before any datagram, want only the seeded counter", got)
	}
	if got := testutil.CollectAndCount(c, "xflow_domains_refused_total"); got != 1 {
		t.Errorf("refusal counter series = %d, want 1 seeded", got)
	}
}

func TestDecoderCollector_ReportsOutcomes(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
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

// buildV9TemplateOnly crafts a v9 datagram announcing one two-field template
// so the domain series gain a subject.
func buildV9TemplateOnly() []byte {
	return []byte{
		0x00, 0x09, 0x00, 0x01, // version 9, count 1
		0x00, 0x00, 0x00, 0x00, // sysUptime
		0x68, 0x00, 0x00, 0x00, // unix_secs
		0x00, 0x00, 0x00, 0x05, // sequence 5
		0x00, 0x00, 0x01, 0x00, // source id 256
		// template flowset: id 0, length 16, template 300 with two fields
		0x00, 0x00, 0x00, 0x10,
		0x01, 0x2C, 0x00, 0x02,
		0x00, 0x01, 0x00, 0x04, // IN_BYTES(4)
		0x00, 0x02, 0x00, 0x04, // IN_PKTS(4)
	}
}

func TestDecoderCollector_ReportsDomainState(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.20")

	if _, err := d.Decode(exporter, buildV9TemplateOnly(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_sequence_missed_total Export packets the sequence numbers say were lost, per observation domain
# TYPE xflow_sequence_missed_total counter
xflow_sequence_missed_total{exporter="192.0.2.20",odid="256"} 0
# HELP xflow_templates Unexpired templates held per exporter, observation domain and kind
# TYPE xflow_templates gauge
xflow_templates{exporter="192.0.2.20",odid="256",type="options_template"} 0
xflow_templates{exporter="192.0.2.20",odid="256",type="template"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_templates", "xflow_sequence_missed_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}

	// No options arrived, so no sampling rate series exists.
	if got := testutil.CollectAndCount(c, "xflow_sampling_rate"); got != 0 {
		t.Errorf("sampling rate series = %d, want 0 until a rate arrives", got)
	}
}

func TestCollector_RegisterDecoderCollector(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterDecoderCollector(newTestDecoder())

	// The registry accepts the collector; series appear with traffic.
	if _, err := c.Registry().Gather(); err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
}
