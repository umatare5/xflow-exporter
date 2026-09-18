package collector

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// TestDistributions_LeaveAnAggregateUnobserved pins the histogram gate. A v8
// aggregate's byte count is the sum of the flows it folded and its span is
// the cache's, so observing either reports a flow the device never measured.
func TestDistributions_LeaveAnAggregateUnobserved(t *testing.T) {
	t.Parallel()

	d := NewDistributions()
	reg := prometheus.NewRegistry()
	d.Register(reg)

	boot := time.Unix(1_756_300_000, 0)
	base := flow.Record{
		Exporter:      netip.MustParseAddr("192.0.2.22"),
		Flows:         9,
		Bytes:         90000,
		BytesReported: true,
		Start:         boot,
		End:           boot.Add(10 * time.Second),
	}
	perFlow, aggregate := base, base
	perFlow.Version = flow.VersionNetFlowV5
	aggregate.Version = flow.VersionNetFlowV8

	d.Observe([]flow.Record{perFlow, aggregate})

	if got := testutil.CollectAndCount(d.flowBytes); got != 1 {
		t.Errorf("xflow_flow_bytes = %d series, want the per-flow record alone", got)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if got := metric.GetHistogram().GetSampleCount(); got != 1 {
				t.Errorf("%s count = %d, want the one record that measured a flow", family.GetName(), got)
			}
		}
	}
}

// TestDistributions_HoldResolutionOverTheCorrectedSpan pins the cap against
// the width a device's range takes, below which the schema halves.
func TestDistributions_HoldResolutionOverTheCorrectedSpan(t *testing.T) {
	t.Parallel()

	// One value per schema-3 bucket, across a width past what a device
	// exporting both corrected and uncorrected records takes.
	const (
		keysPerOctave = 8
		octaves       = 23
		smallest      = 64
	)

	d := NewDistributions()
	reg := prometheus.NewRegistry()
	d.Register(reg)

	records := make([]flow.Record, 0, keysPerOctave*octaves)
	for i := range keysPerOctave * octaves {
		records = append(records, flow.Record{
			Exporter:      netip.MustParseAddr("192.0.2.1"),
			Version:       flow.VersionNetFlowV9,
			Bytes:         uint64(math.Pow(2, float64(i)/keysPerOctave) * smallest),
			Packets:       1,
			BytesReported: true,
			Flows:         1,
		})
	}
	d.Observe(records)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, mf := range families {
		if mf.GetName() != "xflow_flow_bytes" {
			continue
		}
		// The cap counts populated keys, not span length.
		h := mf.GetMetric()[0].GetHistogram()
		buckets, count := 0, int64(0)
		for _, delta := range h.GetPositiveDelta() {
			count += delta
			if count > 0 {
				buckets++
			}
		}
		if got := h.GetSchema(); got != 3 {
			t.Errorf("schema = %d after %d buckets, want 3 kept", got, buckets)
		}
		if buckets <= 100 {
			t.Errorf("populated buckets = %d, want the span to pass the former cap", buckets)
		}
		return
	}
	t.Fatal("xflow_flow_bytes was not gathered")
}
