package collector

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// TestFlowCollector_WithholdsTheFamilyNoDeviceMeasured pins the absence rule
// on the two counted families. A template keeping its counters in elements
// this decoder does not read leaves the count at zero, and a zero total reads
// exactly like a device that carried nothing -- so the family is withheld
// while the flow count, which every record carries, is published throughout.
func TestFlowCollector_WithholdsTheFamilyNoDeviceMeasured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		bytes      bool
		packets    bool
		wantSeries []string
		wantAbsent []string
	}{
		{
			name: "both measured", bytes: true, packets: true,
			wantSeries: []string{"xflow_host_pair_bytes_total", "xflow_host_pair_packets_total"},
		},
		{
			name: "no byte count", bytes: false, packets: true,
			wantSeries: []string{"xflow_host_pair_packets_total"},
			wantAbsent: []string{"xflow_host_pair_bytes_total"},
		},
		{
			name: "no packet count", bytes: true, packets: false,
			wantSeries: []string{"xflow_host_pair_bytes_total"},
			wantAbsent: []string{"xflow_host_pair_packets_total"},
		},
		{
			name:       "neither measured",
			wantAbsent: []string{"xflow_host_pair_bytes_total", "xflow_host_pair_packets_total"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			agg := aggregator.New(aggConfig(), aggregator.Modules{Hosts: true})
			r := flowRecord("10.0.0.1", "10.0.0.2", 1500)
			r.BytesReported, r.PacketsReported = tc.bytes, tc.packets
			r.Packets = 10
			agg.Ingest([]flow.Record{r})

			c := NewFlowCollector(agg, config.Collectors{Hosts: true}, aggConfig(), nil, nil)

			// The fold is published whatever an entry holds, so the entry's
			// own series is the one past it.
			const fold = 1
			for _, name := range tc.wantSeries {
				if got := testutil.CollectAndCount(c, name); got != fold+1 {
					t.Errorf("%s = %d series, want the entry beside the fold", name, got)
				}
			}
			for _, name := range tc.wantAbsent {
				if got := testutil.CollectAndCount(c, name); got != fold {
					t.Errorf("%s = %d series, want the fold alone", name, got)
				}
			}
			if got := testutil.CollectAndCount(c, "xflow_host_pair_flows_total"); got != fold+1 {
				t.Errorf("xflow_host_pair_flows_total = %d series, want it published throughout", got)
			}
		})
	}
}

// TestFlowCollector_AMixedKeyStaysWithheld pins the rule that makes the
// withholding safe. One unmeasured record leaves the entry's sum short of the
// traffic it names, and every complete record after it makes the shortfall
// harder to see rather than smaller -- a partial total no reader can tell
// from a measured one is the fault a fabricated zero carries.
func TestFlowCollector_AMixedKeyStaysWithheld(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{Hosts: true})

	unmeasured := flowRecord("10.0.0.1", "10.0.0.2", 0)
	unmeasured.BytesReported, unmeasured.PacketsReported = false, true
	unmeasured.Packets = 1
	agg.Ingest([]flow.Record{unmeasured})

	for range 10 {
		measured := flowRecord("10.0.0.1", "10.0.0.2", 1500)
		measured.PacketsReported, measured.Packets = true, 10
		agg.Ingest([]flow.Record{measured})
	}

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, aggConfig(), nil, nil)

	if got := testutil.CollectAndCount(c, "xflow_host_pair_bytes_total"); got != 1 {
		t.Errorf("xflow_host_pair_bytes_total = %d series, want the fold alone", got)
	}
	if got := testutil.CollectAndCount(c, "xflow_host_pair_packets_total"); got != 2 {
		t.Errorf("xflow_host_pair_packets_total = %d series, want the family the device did measure", got)
	}
}

// TestFlowCollector_TheFoldPublishesWhateverItHolds pins the one exception.
// The bucket is a lower bound by construction, the tail below the cut being
// no part of it either, so withholding it for an unmeasured contribution
// trades an understatement for a missing series.
func TestFlowCollector_TheFoldPublishesWhateverItHolds(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.MaxEntries = 1
	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})

	held := flowRecord("10.0.0.1", "10.0.0.2", 1500)
	held.PacketsReported, held.Packets = true, 10
	folded := flowRecord("10.0.0.3", "10.0.0.4", 0)
	folded.BytesReported, folded.PacketsReported = false, false
	agg.Ingest([]flow.Record{held, folded})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	const want = `# HELP xflow_host_pair_bytes_total Sampling-corrected bytes per source-destination pair, other carries the entry-bound fold
# TYPE xflow_host_pair_bytes_total counter
xflow_host_pair_bytes_total{direction="other",dst="other",exporter_address="other",input_ifindex="other",output_ifindex="other",src="other"} 0
xflow_host_pair_bytes_total{direction="unknown",dst="10.0.0.2",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",src="10.0.0.1"} 1500
`

	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"xflow_host_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() error = %v", err)
	}
}
