package collector

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// BenchmarkPublished measures one table's scrape-time cut at the shipped
// bounds: an entry table at --aggregation.max-entries publishing Top-K.
func BenchmarkPublished(b *testing.B) {
	const entries = config.DefaultAggregationMaxEntries

	source := make([]aggregator.EntrySnapshot[int], entries)
	for i := range source {
		source[i].Key = i
		source[i].Born = uint64(i)
		source[i].Bytes = rand.Uint64N(1 << 40)
	}
	work := make([]aggregator.EntrySnapshot[int], entries)
	c := &FlowCollector{topK: config.DefaultAggregationTopK}

	b.ReportAllocs()
	for b.Loop() {
		copy(work, source)
		published(c, work)
	}
}

// BenchmarkDistributions_Observe measures the histogram path over one read's
// worth of records. A batch arrives datagram by datagram, so the devices come
// in runs rather than interleaved.
func BenchmarkDistributions_Observe(b *testing.B) {
	const (
		devices          = 4
		recordsPerDevice = 30
	)

	d := NewDistributions()
	records := make([]flow.Record, 0, devices*recordsPerDevice)
	for i := range devices {
		exporter := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		for j := range recordsPerDevice {
			start := time.Unix(1_756_300_000, 0)
			records = append(records, flow.Record{
				Exporter:      exporter,
				Version:       flow.VersionNetFlowV9,
				Bytes:         uint64(j+1) * 1000,
				BytesReported: true,
				SamplingRate:  100,
				Start:         start,
				End:           start.Add(time.Duration(j+1) * time.Second),
			})
		}
	}

	b.ReportAllocs()
	for b.Loop() {
		d.Observe(records)
	}
}
