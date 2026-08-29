package collector

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil/promlint"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// TestAllCollectors_MetricNamesMatchTypes lints the whole metric surface with
// every collector registered and fed, so the correspondence promlint checks
// covers the real families rather than a hand-kept list.
func TestAllCollectors_MetricNamesMatchTypes(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Collectors = config.Collectors{
		Exporters: true, Hosts: true, Services: true,
		ASNs: true, Applications: true, Distributions: true,
	}
	cfg.Aggregation = config.Aggregation{
		EntryTTL:   config.DefaultAggregationEntryTTL,
		MaxEntries: config.DefaultAggregationMaxEntries,
		TopK:       config.DefaultAggregationTopK,
		MinBytes:   config.DefaultAggregationMinBytes,
	}

	c := NewCollector(cfg)
	c.Setup("test")

	recv := receiver.New(config.Receiver{
		Addresses:     []string{":2055"},
		BatchSize:     config.DefaultReceiverBatchSize,
		QueueSize:     16,
		MaxPacketSize: config.DefaultReceiverMaxPacketSize,
	})
	c.RegisterReceiverCollector(recv)

	dec := newTestDecoder()
	if _, err := dec.Decode(netip.MustParseAddr("192.0.2.30"), buildV5(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	c.RegisterDecoderCollector(dec)

	agg := aggregator.New(cfg.Aggregation, aggregator.Modules{
		Exporters: true, Hosts: true, Services: true, ASNs: true, Applications: true,
	})
	r := flowRecord("10.0.0.1", "10.0.0.2", 1000)
	r.SrcAS, r.DstAS = 64500, 64501
	r.AppName = "https"
	agg.Ingest([]flow.Record{r})
	c.RegisterFlowCollector(agg, cfg.Collectors, cfg.Aggregation)

	dist := c.RegisterDistributions()
	dist.Observe([]flow.Record{r})

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
	if len(families) < 15 {
		t.Fatalf("gathered %d families, too few for the lint below to prove anything", len(families))
	}

	problems, err := promlint.NewWithMetricFamilies(families).Lint()
	if err != nil {
		t.Fatalf("Lint() error = %v, want nil", err)
	}
	for _, problem := range problems {
		t.Errorf("%s: %s", problem.Metric, problem.Text)
	}
}
