package collector

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
	dto "github.com/prometheus/client_model/go"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/enrich"
	"github.com/umatare5/xflow-exporter/internal/flow"
	"github.com/umatare5/xflow-exporter/internal/receiver"
	"github.com/umatare5/xflow-exporter/internal/remotewrite"
)

// TestFlowCollector_SurvivesAnUnrepresentableLabelValue pins the containment
// rather than the guard. The decoder refuses a vendor string Prometheus
// cannot hold, which is where the wire path is closed, so this test sets the
// label value directly to stand for any future path that reaches one. What
// the collector owes such a value is the entry it belongs to and nothing
// else.
func TestFlowCollector_SurvivesAnUnrepresentableLabelValue(t *testing.T) {
	t.Parallel()

	// A name cut mid rune by a fixed-width export field.
	truncated := "アプリ"[:8]
	if utf8.ValidString(truncated) {
		t.Fatal("the fixture is valid UTF-8, so it pins nothing")
	}

	clean := gatherFamilyNames(t, "https")
	broken := gatherFamilyNames(t, truncated)

	present := make(map[string]bool, len(broken))
	for _, name := range broken {
		present[name] = true
	}
	// Only the entry carrying the value goes absent. Every family, the one
	// the value belongs to included, still reaches the scrape.
	for _, name := range clean {
		if !present[name] {
			t.Errorf("%s left the scrape because of one wire-controlled label value", name)
		}
	}

	// The family surviving is not the same as its other entries surviving:
	// with one application in the table the two are indistinguishable. The
	// record beside the broken one names an application of its own, and that
	// entry is what the containment is for.
	if got := applicationNames(t, truncated); !slices.Contains(got, neighborApplication) {
		t.Errorf("applications published = %v, want %s beside the refused one", got, neighborApplication)
	}
}

// neighborApplication names the second record every fixture below carries,
// so a containment that abandoned the table rather than the entry is visible.
const neighborApplication = "ssh"

// applicationNames returns the application label of every series the
// application family published.
func applicationNames(t *testing.T, appName string) []string {
	t.Helper()

	var names []string
	for _, f := range gatherFamilies(t, appName) {
		if f.GetName() != "xflow_application_bytes_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "application" {
					names = append(names, l.GetValue())
				}
			}
		}
	}
	return names
}

// gatherFamilyNames returns the name of every family a scrape would publish.
func gatherFamilyNames(t *testing.T, appName string) []string {
	t.Helper()

	families := gatherFamilies(t, appName)
	names := make([]string, 0, len(families))
	for _, f := range families {
		names = append(names, f.GetName())
	}
	return names
}

// gatherFamilies registers every flow collector over two records, one
// carrying the given application name and one naming its neighbor, and
// returns what a scrape would publish.
func gatherFamilies(t *testing.T, appName string) []*dto.MetricFamily {
	t.Helper()

	cfg := testConfig()
	cfg.Collectors = config.Collectors{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		TCPFlags: true, DSCP: true,
		ASNs: true, Applications: true, Countries: true, Threats: true,
	}
	cfg.Aggregation = config.Aggregation{
		EntryTTL:   config.DefaultAggregationEntryTTL,
		MaxEntries: config.DefaultAggregationMaxEntries,
		TopK:       config.DefaultAggregationTopK,
		MinBytes:   config.DefaultAggregationMinBytes,
	}

	c := NewCollector(cfg)
	c.Setup("test")

	agg := aggregator.New(cfg.Aggregation, aggregator.Modules{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		TCPFlags: true, DSCP: true,
		ASNs: true, Applications: true, Countries: true, Threats: true,
	})
	// The families past the application one in Collect order are what an
	// ordering-only containment loses, so they must be filled here.
	r := flowRecord("10.0.0.1", "10.0.0.2", 1000)
	r.SrcAS, r.DstAS = 64500, 64501
	r.AppName = appName
	r.SrcCountry, r.DstCountry = "JP", "US"
	r.SrcFlagged, r.DstFlagged = true, true

	// Fewer bytes, so the entry under test sorts ahead of it and a
	// containment that abandons the table after a failure abandons this.
	neighbor := flowRecord("10.0.0.1", "10.0.0.2", 500)
	neighbor.SrcAS, neighbor.DstAS = r.SrcAS, r.DstAS
	neighbor.SrcCountry, neighbor.DstCountry = r.SrcCountry, r.DstCountry
	neighbor.SrcFlagged, neighbor.DstFlagged = r.SrcFlagged, r.DstFlagged
	neighbor.AppName = neighborApplication
	neighbor.DstPort = 22
	agg.Ingest([]flow.Record{r, neighbor})
	c.RegisterFlowCollector(agg, cfg.Collectors, cfg.Aggregation, func(as uint32) (string, bool) {
		if as == 64500 {
			return "Example Networks", true
		}
		return "", false
	})

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
	return families
}

// TestAllCollectors_MetricNamesMatchTypes lints the whole metric surface with
// every collector registered and fed, so the correspondence promlint checks
// covers the real families rather than a hand-kept list.
func TestAllCollectors_MetricNamesMatchTypes(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Collectors = config.Collectors{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		TCPFlags: true, DSCP: true,
		ASNs: true, Applications: true, Countries: true, Threats: true,
		Distributions: true,
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
	exporter := netip.MustParseAddr("192.0.2.30")
	if _, err := dec.Decode(exporter, buildV5(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	// A rejected datagram and a template announcement, so the families that
	// only a v9 exchange publishes reach the lint below.
	if _, err := dec.Decode(exporter, []byte{0x00, 0x63, 0x00, 0x00}, nil); err == nil {
		t.Fatal("Decode() of an unknown version error = nil, want a rejection")
	}
	if _, err := dec.Decode(exporter, buildV9TemplateOnly(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	c.RegisterDecoderCollector(dec)

	agg := aggregator.New(cfg.Aggregation, aggregator.Modules{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		TCPFlags: true, DSCP: true,
		ASNs: true, Applications: true, Countries: true, Threats: true,
	})
	// Every dimension filled, so no module lints on an empty table.
	r := flowRecord("10.0.0.1", "10.0.0.2", 1000)
	r.SrcAS, r.DstAS = 64500, 64501
	r.AppName = "https"
	r.SrcCountry, r.DstCountry = "JP", "US"
	r.SrcFlagged, r.DstFlagged = true, true
	// Both instants, so the duration histogram is observed rather than
	// skipped and its name reaches the lint below.
	r.Start = time.Unix(1_756_300_000, 0)
	r.End = r.Start.Add(15 * time.Second)
	agg.Ingest([]flow.Record{r})
	c.RegisterFlowCollector(agg, cfg.Collectors, cfg.Aggregation, nil)

	dist := c.RegisterDistributions()
	dist.Observe([]flow.Record{r})

	threat, err := enrich.NewThreat([]string{writeThreatList(t)})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}
	c.RegisterEnrichmentCollector(enrich.NewChain(threat), threat)
	c.RegisterRemoteWriteCollector(&stubRemoteWrite{})

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
	// The count this surface publishes, held exactly rather than as a floor:
	// a floor cannot see a family disappear in the same change that adds
	// another, and the lint below reaches only what was gathered. Two
	// registered families stay outside it -- the sampling rate needs an
	// options template announcing a sampler, and the remote write instant
	// needs a client that has written, whose counters the package keeps
	// unexported. Changing the surface is meant to change this number.
	const wantFamilies = 59
	if len(families) != wantFamilies {
		t.Fatalf("gathered %d families, want %d: the lint below covers only what is registered",
			len(families), wantFamilies)
	}

	problems, err := promlint.NewWithMetricFamilies(families).Lint()
	if err != nil {
		t.Fatalf("Lint() error = %v, want nil", err)
	}
	for _, problem := range problems {
		t.Errorf("%s: %s", problem.Metric, problem.Text)
	}
}

// writeThreatList gives the enrichment collector a real set to report.
func writeThreatList(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("198.51.100.7\nnot-an-address\n"), 0o600); err != nil {
		t.Fatalf("writing the threat list: %v", err)
	}
	return path
}

// stubRemoteWrite brings the remote write families into the lint. The
// counters seed at zero, which is what a configured writer publishes before
// its first send.
type stubRemoteWrite struct{ stats remotewrite.Stats }

func (s *stubRemoteWrite) Stats() *remotewrite.Stats { return &s.stats }
