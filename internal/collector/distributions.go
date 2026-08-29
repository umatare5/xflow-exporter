// This file holds the flow distribution histograms. They are native
// histograms: one series per exporter with exponential buckets, in place of
// the classic per-bucket series fan-out.

package collector

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// Distributions observes per-flow size and duration into native histograms.
// Unlike the table collectors it is written at ingest: a histogram is an
// accumulation, not a snapshot.
type Distributions struct {
	flowBytes    *prometheus.HistogramVec
	flowDuration *prometheus.HistogramVec
}

// NewDistributions creates the histograms. The factor bounds the relative
// bucket error at about five percent, and the bucket cap with the reset
// window bounds memory per series.
func NewDistributions() *Distributions {
	const (
		bucketFactor    = 1.1
		maxBuckets      = 100
		minResetSpacing = time.Hour
	)

	exporterLabels := []string{labelExporter}

	return &Distributions{
		flowBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            "xflow_flow_bytes",
			Help:                            "Sampling-corrected bytes per flow record, as a native histogram",
			NativeHistogramBucketFactor:     bucketFactor,
			NativeHistogramMaxBucketNumber:  maxBuckets,
			NativeHistogramMinResetDuration: minResetSpacing,
		}, exporterLabels),
		flowDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            "xflow_flow_duration_seconds",
			Help:                            "Flow duration where the record carried both instants, as a native histogram",
			NativeHistogramBucketFactor:     bucketFactor,
			NativeHistogramMaxBucketNumber:  maxBuckets,
			NativeHistogramMinResetDuration: minResetSpacing,
		}, exporterLabels),
	}
}

// Register registers both histograms with the registry.
func (d *Distributions) Register(reg *prometheus.Registry) {
	reg.MustRegister(d.flowBytes, d.flowDuration)
}

// Observe accounts one batch of decoded records.
func (d *Distributions) Observe(records []flow.Record) {
	for i := range records {
		r := &records[i]
		exporter := r.Exporter.String()

		rate := uint64(r.SamplingRate)
		if rate == 0 {
			rate = 1
		}
		d.flowBytes.WithLabelValues(exporter).Observe(float64(r.Bytes * rate))

		// A record without both instants has no duration, and observing a
		// zero would claim an instant flow the device never measured.
		if duration, ok := r.Duration(); ok {
			d.flowDuration.WithLabelValues(exporter).Observe(duration.Seconds())
		}
	}
}
