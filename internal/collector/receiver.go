// Package collector provides collectors for xflow-exporter.
// This file holds the receiver self-monitoring collector. Without it a wedged
// receiver produces a successful scrape carrying no receiver series, which no
// alert can detect.
package collector

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// Drop reasons published in the reason label. Both series are seeded so a
// first drop is a rise on a series that was already there.
const (
	dropReasonQueueFull = "queue_full"
	dropReasonTruncated = "truncated"
)

// ReceiverSource is what this collector reads from the receiver.
type ReceiverSource interface {
	Stats() *receiver.Stats
	QueueLength() int
	QueueCapacity() int
}

// ReceiverCollector reports the health of the UDP receive path itself.
type ReceiverCollector struct {
	src ReceiverSource

	packetsDesc    *prometheus.Desc
	bytesDesc      *prometheus.Desc
	readErrorsDesc *prometheus.Desc
	droppedDesc    *prometheus.Desc
	queueLenDesc   *prometheus.Desc
	queueCapDesc   *prometheus.Desc
}

// NewReceiverCollector creates a collector reporting receiver health.
func NewReceiverCollector(src ReceiverSource) *ReceiverCollector {
	listenerLabels := []string{labelListener}

	return &ReceiverCollector{
		src: src,
		packetsDesc: prometheus.NewDesc(
			"xflow_receiver_packets_total",
			"Datagrams received per listener since process start, dropped ones included",
			listenerLabels, nil,
		),
		bytesDesc: prometheus.NewDesc(
			"xflow_receiver_bytes_total",
			"Datagram payload bytes received per listener since process start",
			listenerLabels, nil,
		),
		readErrorsDesc: prometheus.NewDesc(
			"xflow_receiver_read_errors_total",
			"Socket read failures per listener since process start",
			listenerLabels, nil,
		),
		droppedDesc: prometheus.NewDesc(
			"xflow_receiver_dropped_packets_total",
			"Datagrams dropped before decoding per listener and reason since process start",
			[]string{labelListener, labelReason}, nil,
		),
		queueLenDesc: prometheus.NewDesc(
			"xflow_receiver_queue_length",
			"Datagrams waiting between the read loops and the decoders",
			nil, nil,
		),
		queueCapDesc: prometheus.NewDesc(
			"xflow_receiver_queue_capacity",
			"Bound of the queue between the read loops and the decoders",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *ReceiverCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsDesc
	ch <- c.bytesDesc
	ch <- c.readErrorsDesc
	ch <- c.droppedDesc
	ch <- c.queueLenDesc
	ch <- c.queueCapDesc
}

// Collect implements prometheus.Collector by reading the receiver counters.
func (c *ReceiverCollector) Collect(ch chan<- prometheus.Metric) {
	for _, snap := range c.src.Stats().Snapshot() {
		ch <- prometheus.MustNewConstMetric(
			c.packetsDesc, prometheus.CounterValue, float64(snap.Packets), snap.Listener)
		ch <- prometheus.MustNewConstMetric(
			c.bytesDesc, prometheus.CounterValue, float64(snap.Bytes), snap.Listener)
		ch <- prometheus.MustNewConstMetric(
			c.readErrorsDesc, prometheus.CounterValue, float64(snap.ReadErrors), snap.Listener)
		ch <- prometheus.MustNewConstMetric(
			c.droppedDesc, prometheus.CounterValue,
			float64(snap.DroppedQueueFull), snap.Listener, dropReasonQueueFull)
		ch <- prometheus.MustNewConstMetric(
			c.droppedDesc, prometheus.CounterValue,
			float64(snap.DroppedTruncated), snap.Listener, dropReasonTruncated)
	}

	ch <- prometheus.MustNewConstMetric(
		c.queueLenDesc, prometheus.GaugeValue, float64(c.src.QueueLength()))
	ch <- prometheus.MustNewConstMetric(
		c.queueCapDesc, prometheus.GaugeValue, float64(c.src.QueueCapacity()))
}
