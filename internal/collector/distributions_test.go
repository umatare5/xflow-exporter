package collector

import (
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
