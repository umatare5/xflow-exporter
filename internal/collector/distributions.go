// This file holds the flow distribution histograms. They are native
// histograms: one series per exporter with exponential buckets, in place of
// the classic per-bucket series fan-out.

package collector

import (
	"net/netip"
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
// bucket error at about five percent, and the cap with the reset window
// bounds memory per series. The cap holds a range's width, not its scale.
func NewDistributions() *Distributions {
	const (
		bucketFactor    = 1.1
		maxBuckets      = 200
		minResetSpacing = time.Hour
	)

	exporterLabels := []string{labelExporter}

	return &Distributions{
		flowBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            "xflow_flow_bytes",
			Help:                            "Sampling-corrected bytes per flow record where the record carried a byte count, as a native histogram",
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

// Forget drops the device's histograms, which a vector keeps until deleted.
func (d *Distributions) Forget(exporter netip.Addr) {
	label := exporter.String()
	d.flowBytes.DeleteLabelValues(label)
	d.flowDuration.DeleteLabelValues(label)
}

// Register registers both histograms with the registry.
func (d *Distributions) Register(reg *prometheus.Registry) {
	reg.MustRegister(d.flowBytes, d.flowDuration)
}

// Observe accounts one batch of decoded records.
//
// The two observers are resolved per device rather than per record. A batch
// is read datagram by datagram and a datagram carries one device, so the
// records of one device arrive together and the address renders once for the
// run rather than once for each of its records.
func (d *Distributions) Observe(records []flow.Record) {
	var (
		current             netip.Addr
		bytesOf, durationOf prometheus.Observer
	)

	for i := range records {
		r := &records[i]
		// An aggregate holds several flows, so its size is not a flow size
		// and its span is not a flow duration.
		if r.Aggregated() {
			continue
		}

		if bytesOf == nil || r.Exporter != current {
			exporter := r.Exporter.String()
			current = r.Exporter
			bytesOf = d.flowBytes.WithLabelValues(exporter)
			durationOf = d.flowDuration.WithLabelValues(exporter)
		}

		// A record whose counters rode elements the decoder does not read has
		// no byte count, and a zero would claim an empty flow nobody measured.
		if r.BytesReported {
			bytes, _ := r.Corrected()
			bytesOf.Observe(float64(bytes))
		}

		// A record without both instants has no duration, and observing a
		// zero would claim an instant flow the device never measured.
		if duration, ok := r.Duration(); ok {
			durationOf.Observe(duration.Seconds())
		}
	}
}
