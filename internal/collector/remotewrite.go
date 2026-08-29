// Package collector provides collectors for xflow-exporter.
// This file holds the remote write self-monitoring collector.
package collector

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/remotewrite"
)

// RemoteWriteSource is what this collector reads from the writer.
type RemoteWriteSource interface {
	Stats() *remotewrite.Stats
}

// RemoteWriteCollector reports whether the registry is reaching the remote
// endpoint. Without it a client that has failed every write since start-up
// looks exactly like one nobody enabled.
type RemoteWriteCollector struct {
	src RemoteWriteSource

	sendsDesc       *prometheus.Desc
	failuresDesc    *prometheus.Desc
	samplesDesc     *prometheus.Desc
	lastSuccessDesc *prometheus.Desc
}

// NewRemoteWriteCollector creates a collector over the writer.
func NewRemoteWriteCollector(src RemoteWriteSource) *RemoteWriteCollector {
	return &RemoteWriteCollector{
		src: src,
		sendsDesc: prometheus.NewDesc(
			"xflow_remote_write_sends_total",
			"Writes the remote endpoint accepted since process start",
			nil, nil,
		),
		failuresDesc: prometheus.NewDesc(
			"xflow_remote_write_failures_total",
			"Writes that failed since process start, a gather failure included",
			nil, nil,
		),
		samplesDesc: prometheus.NewDesc(
			"xflow_remote_write_samples_total",
			"Samples shipped since process start, one per series per write",
			nil, nil,
		),
		lastSuccessDesc: prometheus.NewDesc(
			"xflow_remote_write_last_success_timestamp_seconds",
			"Unix time of the last accepted write, absent until one succeeds",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *RemoteWriteCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sendsDesc
	ch <- c.failuresDesc
	ch <- c.samplesDesc
	ch <- c.lastSuccessDesc
}

// Collect implements prometheus.Collector by reading the write counters.
func (c *RemoteWriteCollector) Collect(ch chan<- prometheus.Metric) {
	const nanosPerSecond = 1e9

	snap := c.src.Stats().Snapshot()

	ch <- prometheus.MustNewConstMetric(c.sendsDesc, prometheus.CounterValue, float64(snap.Sends))
	ch <- prometheus.MustNewConstMetric(c.failuresDesc, prometheus.CounterValue, float64(snap.Failures))
	ch <- prometheus.MustNewConstMetric(c.samplesDesc, prometheus.CounterValue, float64(snap.Samples))

	// A client that has never succeeded has no instant: a zero would read as
	// a write in 1970.
	if snap.LastSuccessUnixNano > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.lastSuccessDesc, prometheus.GaugeValue,
			float64(snap.LastSuccessUnixNano)/nanosPerSecond)
	}
}
