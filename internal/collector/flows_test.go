package collector

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

func aggConfig() config.Aggregation {
	return config.Aggregation{
		EntryTTL:   config.DefaultAggregationEntryTTL,
		MaxEntries: config.DefaultAggregationMaxEntries,
		TopK:       config.DefaultAggregationTopK,
		MinBytes:   config.DefaultAggregationMinBytes,
	}
}

func flowRecord(src, dst string, bytes uint64) flow.Record {
	return flow.Record{
		Exporter: netip.MustParseAddr("192.0.2.1"),
		Version:  flow.VersionNetFlowV9,
		SrcAddr:  netip.MustParseAddr(src),
		DstAddr:  netip.MustParseAddr(dst),
		DstPort:  443,
		Protocol: 6,
		Bytes:    bytes,
		Packets:  1,
		Flows:    1,
	}
}

func TestFlowCollector_PublishesExportersAndHosts(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{Exporters: true, Hosts: true}
	agg := aggregator.New(aggConfig(), aggregator.Modules{Exporters: true, Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.2", 1000),
		flowRecord("10.0.0.1", "10.0.0.2", 500),
	})

	c := NewFlowCollector(agg, modules, aggConfig())

	expected := `
# HELP xflow_exporter_bytes_total Sampling-corrected bytes per exporter and version, other folds the rest
# TYPE xflow_exporter_bytes_total counter
xflow_exporter_bytes_total{exporter="192.0.2.1",version="netflow_v9"} 1500
xflow_exporter_bytes_total{exporter="other",version="other"} 0
# HELP xflow_host_pair_flows_total Flow records as exported per source-destination pair, other folds the rest
# TYPE xflow_host_pair_flows_total counter
xflow_host_pair_flows_total{dst="10.0.0.2",exporter="192.0.2.1",src="10.0.0.1"} 2
xflow_host_pair_flows_total{dst="other",exporter="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_exporter_bytes_total", "xflow_host_pair_flows_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_TopKWithholdsTheLiveTail pins that entries below the cut
// are withheld rather than summed into other. Their totals are still moving,
// so adding them per scrape would make the other counter fall whenever one is
// evicted or grows into the cut.
func TestFlowCollector_TopKWithholdsTheLiveTail(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 2

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.9", 5000),
		flowRecord("10.0.0.2", "10.0.0.9", 3000),
		flowRecord("10.0.0.3", "10.0.0.9", 100),
		flowRecord("10.0.0.4", "10.0.0.9", 50),
	})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg)

	expected := `
# HELP xflow_host_pair_bytes_total Sampling-corrected bytes per source-destination pair, other folds the rest
# TYPE xflow_host_pair_bytes_total counter
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter="192.0.2.1",src="10.0.0.1"} 5000
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter="192.0.2.1",src="10.0.0.2"} 3000
xflow_host_pair_bytes_total{dst="other",exporter="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_host_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_MinBytesWithholdsMice pins the same contract for the byte
// threshold: a mouse flow is withheld while it lives and reaches other only
// once it is evicted.
func TestFlowCollector_MinBytesWithholdsMice(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.MinBytes = 1000

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.9", 5000),
		flowRecord("10.0.0.2", "10.0.0.9", 999),
	})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg)

	expected := `
# HELP xflow_host_pair_bytes_total Sampling-corrected bytes per source-destination pair, other folds the rest
# TYPE xflow_host_pair_bytes_total counter
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter="192.0.2.1",src="10.0.0.1"} 5000
xflow_host_pair_bytes_total{dst="other",exporter="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_host_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestFlowCollector_ServiceAndASNAndApplicationLabels(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{Services: true, ASNs: true, Applications: true}
	agg := aggregator.New(aggConfig(),
		aggregator.Modules{Services: true, ASNs: true, Applications: true})

	r := flowRecord("10.0.0.1", "10.0.0.2", 700)
	r.SrcAS, r.DstAS = 64500, 64501
	r.AppName = "https"
	agg.Ingest([]flow.Record{r})

	c := NewFlowCollector(agg, modules, aggConfig())

	expected := `
# HELP xflow_application_bytes_total Sampling-corrected bytes per application, other folds the rest
# TYPE xflow_application_bytes_total counter
xflow_application_bytes_total{application="https",exporter="192.0.2.1"} 700
xflow_application_bytes_total{application="other",exporter="other"} 0
# HELP xflow_asn_pair_bytes_total Sampling-corrected bytes per AS pair, other folds the rest
# TYPE xflow_asn_pair_bytes_total counter
xflow_asn_pair_bytes_total{dst_asn="64501",exporter="192.0.2.1",src_asn="64500"} 700
xflow_asn_pair_bytes_total{dst_asn="other",exporter="other",src_asn="other"} 0
# HELP xflow_service_bytes_total Sampling-corrected bytes per service five-tuple, other folds the rest
# TYPE xflow_service_bytes_total counter
xflow_service_bytes_total{dst="10.0.0.2",exporter="192.0.2.1",port="443",proto="tcp",src="10.0.0.1"} 700
xflow_service_bytes_total{dst="other",exporter="other",port="other",proto="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_service_bytes_total", "xflow_asn_pair_bytes_total",
		"xflow_application_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestFlowCollector_HealthSeries(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{flowRecord("10.0.0.1", "10.0.0.2", 10)})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, aggConfig())

	expected := `
# HELP xflow_aggregation_entries Entries held per aggregation table
# TYPE xflow_aggregation_entries gauge
xflow_aggregation_entries{aggregation="hosts"} 1
# HELP xflow_aggregation_evictions_total Idle entries evicted per aggregation table since process start
# TYPE xflow_aggregation_evictions_total counter
xflow_aggregation_evictions_total{aggregation="hosts"} 0
# HELP xflow_aggregation_overflow_records_total Records folded into other by the entry bound since process start
# TYPE xflow_aggregation_overflow_records_total counter
xflow_aggregation_overflow_records_total{aggregation="hosts"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_aggregation_entries", "xflow_aggregation_evictions_total",
		"xflow_aggregation_overflow_records_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestProtocolName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		protocol uint8
		want     string
	}{
		{1, "icmp"},
		{6, "tcp"},
		{17, "udp"},
		{47, "gre"},
		{50, "esp"},
		{51, "ah"},
		{58, "icmpv6"},
		{89, "ospf"},
		{132, "sctp"},
		{200, "200"},
	}
	for _, tt := range tests {
		if got := protocolName(tt.protocol); got != tt.want {
			t.Errorf("protocolName(%d) = %q, want %q", tt.protocol, got, tt.want)
		}
	}
}

func TestDistributions_ObserveWithholdsAbsentDurations(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	d := c.RegisterDistributions()

	r := flowRecord("10.0.0.1", "10.0.0.2", 1500)
	r.SamplingRate = 10
	d.Observe([]flow.Record{r})

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	for _, family := range families {
		switch family.GetName() {
		case "xflow_flow_bytes":
			h := family.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() != 1 || h.GetSampleSum() != 15000 {
				t.Errorf("flow bytes histogram = count %d sum %v, want 1 and the corrected 15000",
					h.GetSampleCount(), h.GetSampleSum())
			}
		case "xflow_flow_duration_seconds":
			h := family.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() != 0 {
				t.Errorf("duration histogram count = %d, want 0 for a record with no instants",
					h.GetSampleCount())
			}
		}
	}
}
