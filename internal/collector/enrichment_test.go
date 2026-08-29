package collector

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/enrich"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

func TestEnrichmentCollector_ReportsEveryOutcome(t *testing.T) {
	t.Parallel()

	chain := enrich.NewChain(enrich.NewServices())
	chain.Enrich([]flow.Record{
		{Protocol: 6, DstPort: 443},                           // filled
		{Protocol: 6, DstPort: 49152},                         // unknown
		{Protocol: 6, DstPort: 443, AppName: "already-named"}, // skipped
	})

	c := NewEnrichmentCollector(chain, nil)

	expected := `
# HELP xflow_enrichment_lookups_total Records each enrichment source saw, by what it made of them, since process start
# TYPE xflow_enrichment_lookups_total counter
xflow_enrichment_lookups_total{enricher="services",result="filled"} 1
xflow_enrichment_lookups_total{enricher="services",result="skipped"} 1
xflow_enrichment_lookups_total{enricher="services",result="unknown"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected)); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestEnrichmentCollector_SeedsEveryOutcome pins that all three results exist
// from the first scrape, so a first fill is a rise rather than a new series.
func TestEnrichmentCollector_SeedsEveryOutcome(t *testing.T) {
	t.Parallel()

	c := NewEnrichmentCollector(enrich.NewChain(enrich.NewServices()), nil)

	if got := testutil.CollectAndCount(c, "xflow_enrichment_lookups_total"); got != 3 {
		t.Errorf("series = %d before any record, want the three outcomes seeded", got)
	}
}

func TestCollector_RegisterEnrichmentCollector(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterEnrichmentCollector(enrich.NewChain(enrich.NewServices()), nil)

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	found := false
	for _, family := range families {
		if family.GetName() == "xflow_enrichment_lookups_total" {
			found = true
		}
	}
	if !found {
		t.Error("xflow_enrichment_lookups_total is absent, want the collector registered")
	}
}
