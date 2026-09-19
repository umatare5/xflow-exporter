package collector

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// TestDistributions_PublishNothingTheyDidNotObserve is the regression test for
// the fabricated zero. A vector publishes a child the moment it is asked for
// one, so an observer resolved alongside the device address rather than with
// its own first reading gives every sFlow agent a duration count of zero --
// which reads as a device that measured no flow duration rather than one that
// measures none.
func TestDistributions_PublishNothingTheyDidNotObserve(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_756_300_000, 0)
	tests := []struct {
		name   string
		record flow.Record
		want   []string
	}{
		{
			name:   "a sampled packet, which carries no clock",
			record: flow.Record{Bytes: 1500, BytesReported: true},
			want:   []string{"xflow_flow_bytes"},
		},
		{
			name:   "a clock whose record carried no byte count",
			record: flow.Record{Start: at, End: at.Add(2 * time.Second)},
			want:   []string{"xflow_flow_duration_seconds"},
		},
		{
			name: "both measured",
			record: flow.Record{
				Bytes: 1500, BytesReported: true,
				Start: at, End: at.Add(2 * time.Second),
			},
			want: []string{"xflow_flow_bytes", "xflow_flow_duration_seconds"},
		},
		{
			name:   "an aggregate, whose span is not a flow duration",
			record: flow.Record{Version: flow.VersionNetFlowV8, Bytes: 1500, BytesReported: true},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			d := NewDistributions()
			d.Register(reg)

			tt.record.Exporter = netip.MustParseAddr("192.0.2.1")
			d.Observe([]flow.Record{tt.record})

			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather() error = %v, want nil", err)
			}
			got := make([]string, 0, len(families))
			for _, f := range families {
				got = append(got, f.GetName())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("gathered %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDistributions_ResolveEachDeviceOnce pins that the run cache survives the
// change: the records of one device arrive together, so a device whose every
// record measures both still renders its address once.
func TestDistributions_ResolveEachDeviceOnce(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_756_300_000, 0)
	records := make([]flow.Record, 0, 6)
	for _, addr := range []string{"192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.2", "192.0.2.1"} {
		records = append(records, flow.Record{
			Exporter:      netip.MustParseAddr(addr),
			Bytes:         1500,
			BytesReported: true,
			Start:         at,
			End:           at.Add(time.Second),
		})
	}

	reg := prometheus.NewRegistry()
	d := NewDistributions()
	d.Register(reg)
	d.Observe(records)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
	for _, f := range families {
		if got := len(f.GetMetric()); got != 2 {
			t.Errorf("%s published %d series, want one per device", f.GetName(), got)
		}
		for _, m := range f.GetMetric() {
			if got := m.GetHistogram().GetSampleCount(); got == 0 {
				t.Errorf("%s series %v observed nothing", f.GetName(), m.GetLabel())
			}
		}
	}
}
