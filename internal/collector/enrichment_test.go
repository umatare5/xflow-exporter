package collector

import (
	"os"
	"path/filepath"
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

// TestEnrichmentCollector_ReportsTheThreatSet pins the wiring of every threat
// series to the field it reports. The four are adjacent lines of near-identical
// shape, so the natural slip is to cross two of them, and a fixture whose
// counts coincide cannot tell a crossed pair from a correct one -- the list
// here holds a different number of addresses than it skipped lines.
func TestEnrichmentCollector_ReportsTheThreatSet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "list.txt")
	content := "198.51.100.7\n203.0.113.9\n192.0.2.1\n" + // three addresses
		"203.0.113.0/24\nnot-an-address\n" // two lines naming none
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the list: %v", err)
	}

	threat, err := enrich.NewThreat([]string{path})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	c := NewEnrichmentCollector(enrich.NewChain(threat), threat)

	expected := `
# HELP xflow_threat_entries Flagged addresses held from the threat list files
# TYPE xflow_threat_entries gauge
xflow_threat_entries 3
# HELP xflow_threat_reload_failures_total Threat list loads that failed since process start, each keeping the previous set
# TYPE xflow_threat_reload_failures_total counter
xflow_threat_reload_failures_total 0
# HELP xflow_threat_reloads_total Threat list loads that succeeded since process start, the initial one included
# TYPE xflow_threat_reloads_total counter
xflow_threat_reloads_total 1
# HELP xflow_threat_skipped_lines Lines of the threat list files that name no address, in the set in force
# TYPE xflow_threat_skipped_lines gauge
xflow_threat_skipped_lines 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_threat_entries", "xflow_threat_skipped_lines",
		"xflow_threat_reloads_total", "xflow_threat_reload_failures_total"); err != nil {
		t.Error(err)
	}
}

// TestEnrichmentCollector_ThreatSeriesAreAbsentWithoutAList pins that the
// module publishes nothing rather than zeros when no list is configured.
func TestEnrichmentCollector_ThreatSeriesAreAbsentWithoutAList(t *testing.T) {
	t.Parallel()

	c := NewEnrichmentCollector(enrich.NewChain(enrich.NewServices()), nil)

	for _, name := range []string{
		"xflow_threat_entries", "xflow_threat_skipped_lines",
		"xflow_threat_reloads_total", "xflow_threat_reload_failures_total",
	} {
		if got := testutil.CollectAndCount(c, name); got != 0 {
			t.Errorf("%s = %d series without a list, want none", name, got)
		}
	}
}
