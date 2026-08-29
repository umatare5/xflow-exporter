// Package collector provides collectors for xflow-exporter.
// This file holds the decode self-monitoring collector.
package collector

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/decoder"
)

// DecoderSource is what this collector reads from the decode stage.
type DecoderSource interface {
	Stats() *decoder.Stats
}

// DecoderCollector reports what the decoders made of the received datagrams.
// Exporter devices appear on their first datagram: a push protocol cannot
// know its senders in advance, so nothing is seeded per device.
type DecoderCollector struct {
	src DecoderSource

	flowsDesc    *prometheus.Desc
	errorsDesc   *prometheus.Desc
	lastFlowDesc *prometheus.Desc
}

// NewDecoderCollector creates a collector reporting decode outcomes.
func NewDecoderCollector(src DecoderSource) *DecoderCollector {
	return &DecoderCollector{
		src: src,
		flowsDesc: prometheus.NewDesc(
			"xflow_flows_total",
			"Flow records decoded per exporter and version since process start",
			[]string{labelExporter, labelVersion}, nil,
		),
		errorsDesc: prometheus.NewDesc(
			"xflow_decode_errors_total",
			"Datagrams rejected per exporter, version and reason since process start",
			[]string{labelExporter, labelVersion, labelReason}, nil,
		),
		lastFlowDesc: prometheus.NewDesc(
			"xflow_last_flow_timestamp_seconds",
			"Unix time the exporter's last datagram decoded, absent until one has",
			[]string{labelExporter}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *DecoderCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.flowsDesc
	ch <- c.errorsDesc
	ch <- c.lastFlowDesc
}

// Collect implements prometheus.Collector by reading the decode counters.
func (c *DecoderCollector) Collect(ch chan<- prometheus.Metric) {
	const nanosPerSecond = 1e9

	for _, snap := range c.src.Stats().Snapshot() {
		exporter := snap.Exporter.String()

		for _, flows := range snap.Flows {
			ch <- prometheus.MustNewConstMetric(
				c.flowsDesc, prometheus.CounterValue,
				float64(flows.Count), exporter, flows.Version.String())
		}
		for _, errs := range snap.Errors {
			ch <- prometheus.MustNewConstMetric(
				c.errorsDesc, prometheus.CounterValue,
				float64(errs.Count), exporter, errs.Version.String(), errs.Reason)
		}

		// A device that never decoded has no last-flow instant: publishing a
		// zero would read as a flow in 1970.
		if snap.LastFlowUnixNano > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.lastFlowDesc, prometheus.GaugeValue,
				float64(snap.LastFlowUnixNano)/nanosPerSecond, exporter)
		}
	}
}
