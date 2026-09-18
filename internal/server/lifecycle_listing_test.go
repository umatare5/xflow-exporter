package server

import (
	"testing"

	"github.com/umatare5/xflow-exporter/internal/collector"
)

// TestListerOf pins the conversion the listing's registration reads. Without
// it a build with no collector enabled hands New a non-nil interface over a
// nil pointer, and every request to the listing panics on its receiver.
func TestListerOf(t *testing.T) {
	t.Parallel()

	if got := listerOf(nil); got != nil {
		t.Errorf("listerOf(nil) = %v, want a nil interface", got)
	}
	if listerOf(&collector.FlowCollector{}) == nil {
		t.Error("listerOf(a collector) = nil, want the collector exposed")
	}
}
