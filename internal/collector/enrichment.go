// This file holds the enrichment self-monitoring collector.

package collector

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/enrich"
)

// EnrichmentCollector reports what each enabled enrichment source made of the
// records it saw. Without it an enrichment that silently knows nothing is
// indistinguishable from one that was never enabled.
type EnrichmentCollector struct {
	src enrich.Snapshotter
	// threat is the flagged-address source when one is enabled, whose set
	// size and reload outcomes are worth their own series.
	threat *enrich.Threat

	lookupsDesc    *prometheus.Desc
	entriesDesc    *prometheus.Desc
	skippedDesc    *prometheus.Desc
	reloadsDesc    *prometheus.Desc
	reloadFailDesc *prometheus.Desc
}

// NewEnrichmentCollector creates a collector over the enrichment chain.
// threat may be nil, in which case its series are absent rather than zero.
func NewEnrichmentCollector(src enrich.Snapshotter, threat *enrich.Threat) *EnrichmentCollector {
	return &EnrichmentCollector{
		src:    src,
		threat: threat,
		lookupsDesc: prometheus.NewDesc(
			"xflow_enrichment_lookups_total",
			"Records each enrichment source saw, by what it made of them, since process start",
			[]string{labelEnricher, labelResult}, nil,
		),
		entriesDesc: prometheus.NewDesc(
			"xflow_threat_entries",
			"Flagged addresses held from the threat list files",
			nil, nil,
		),
		skippedDesc: prometheus.NewDesc(
			"xflow_threat_skipped_lines",
			"Lines of the threat list files that name no address, in the set in force",
			nil, nil,
		),
		reloadsDesc: prometheus.NewDesc(
			"xflow_threat_reloads_total",
			"Threat list loads that succeeded since process start, the initial one included",
			nil, nil,
		),
		reloadFailDesc: prometheus.NewDesc(
			"xflow_threat_reload_failures_total",
			"Threat list loads that failed since process start, each keeping the previous set",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *EnrichmentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lookupsDesc
	if c.threat != nil {
		ch <- c.entriesDesc
		ch <- c.skippedDesc
		ch <- c.reloadsDesc
		ch <- c.reloadFailDesc
	}
}

// Collect implements prometheus.Collector by reading the lookup counters. All
// three outcomes are published per source, the zeros included, so a first
// filled record is a rise on a series that was already there.
func (c *EnrichmentCollector) Collect(ch chan<- prometheus.Metric) {
	for _, snap := range c.src.Snapshot() {
		for _, outcome := range []struct {
			result string
			count  uint64
		}{
			{enrich.ResultFilled, snap.Filled},
			{enrich.ResultUnknown, snap.Unknown},
			{enrich.ResultSkipped, snap.Skipped},
		} {
			ch <- prometheus.MustNewConstMetric(
				c.lookupsDesc, prometheus.CounterValue,
				float64(outcome.count), snap.Enricher, outcome.result)
		}
	}

	if c.threat == nil {
		return
	}

	stats := c.threat.Stats()
	ch <- prometheus.MustNewConstMetric(c.entriesDesc, prometheus.GaugeValue, float64(stats.Entries))
	ch <- prometheus.MustNewConstMetric(c.skippedDesc, prometheus.GaugeValue, float64(stats.Skipped))
	ch <- prometheus.MustNewConstMetric(c.reloadsDesc, prometheus.CounterValue, float64(stats.Reloads))
	ch <- prometheus.MustNewConstMetric(
		c.reloadFailDesc, prometheus.CounterValue, float64(stats.Failures))
}
