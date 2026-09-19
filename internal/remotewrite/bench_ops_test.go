package remotewrite

import (
	"strconv"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// BenchmarkLabelsOf measures one series' label set, which the writer builds
// for every series of every gather.
func BenchmarkLabelsOf(b *testing.B) {
	const labels = 6

	metric := &dto.Metric{}
	for i := range labels {
		name := "label_" + strconv.Itoa(labels-i)
		value := "value_" + strconv.Itoa(i)
		metric.Label = append(metric.Label, &dto.LabelPair{Name: &name, Value: &value})
	}

	b.ReportAllocs()
	for b.Loop() {
		labelsOf("xflow_host_bytes_total", metric)
	}
}
