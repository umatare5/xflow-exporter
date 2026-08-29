// Package collector provides collectors for xflow-exporter.
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

	lookupsDesc *prometheus.Desc
}

// NewEnrichmentCollector creates a collector over the enrichment chain.
func NewEnrichmentCollector(src enrich.Snapshotter) *EnrichmentCollector {
	return &EnrichmentCollector{
		src: src,
		lookupsDesc: prometheus.NewDesc(
			"xflow_enrichment_lookups_total",
			"Records each enrichment source saw, by what it made of them, since process start",
			[]string{labelEnricher, labelResult}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *EnrichmentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lookupsDesc
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
}
