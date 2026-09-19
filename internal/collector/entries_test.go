package collector

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// TestFlowCollector_EntriesRankTheCut pins what the listing is for: the rows
// the Top-K cut withholds are reported, ranked as the scrape ranks them, and
// counted apart from the entry-bound fold.
func TestFlowCollector_EntriesRankTheCut(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 2

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.3", "10.0.0.9", 100),
		flowRecord("10.0.0.1", "10.0.0.9", 5000),
		flowRecord("10.0.0.5", "10.0.0.9", 7),
		flowRecord("10.0.0.2", "10.0.0.9", 3000),
		flowRecord("10.0.0.4", "10.0.0.9", 50),
	})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	table, ok := c.Entries("hosts")
	if !ok {
		t.Fatal(`Entries("hosts") reported the table absent, want it read`)
	}

	if table.Entries != 5 || table.Published != 2 || table.Withheld != 3 {
		t.Errorf("entries/published/withheld = %d/%d/%d, want 5/2/3",
			table.Entries, table.Published, table.Withheld)
	}
	if got := len(table.Rows); got != 5 {
		t.Fatalf("rows = %d, want every entry listed", got)
	}

	// The tail below the cut is what no series carries, so its totals are the
	// listing's own answer rather than a copy of the other row.
	if got := table.WithheldTotals.Bytes; got != 100+50+7 {
		t.Errorf("withheld_totals.bytes = %d, want 157", got)
	}
	if got := table.Other.Bytes; got != 0 {
		t.Errorf("other.bytes = %d, want the entry-bound fold alone", got)
	}

	wantBytes := []uint64{5000, 3000, 100, 50, 7}
	for i, row := range table.Rows {
		if row.Rank != i+1 {
			t.Errorf("rows[%d].rank = %d, want %d", i, row.Rank, i+1)
		}
		if row.Bytes != wantBytes[i] {
			t.Errorf("rows[%d].bytes = %d, want %d", i, row.Bytes, wantBytes[i])
		}
	}
}

// TestFlowCollector_EntriesLeaveExportersUncut pins the one table the scrape
// publishes whole. Cutting it here would report a withheld set /metrics does
// not have.
func TestFlowCollector_EntriesLeaveExportersUncut(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 1

	const domains = 5

	agg := aggregator.New(cfg, aggregator.Modules{Exporters: true})
	for i := range domains {
		record := flowRecord("10.0.0.1", "10.0.0.9", uint64(i+1)*100)
		record.Exporter = netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1))
		agg.Ingest([]flow.Record{record})
	}

	c := NewFlowCollector(agg, config.Collectors{Exporters: true}, cfg, nil, nil)

	// The snapshot arrives in map order, so the ranks are read more than once:
	// an unsorted listing would have to land on the sorted permutation every
	// time to pass.
	wantBytes := []uint64{500, 400, 300, 200, 100}
	for read := range domains {
		table, ok := c.Entries("exporters")
		if !ok {
			t.Fatal(`Entries("exporters") reported the table absent, want it read`)
		}
		if table.Published != domains || table.Withheld != 0 {
			t.Fatalf("published/withheld = %d/%d, want %d/0 under top-k 1",
				table.Published, table.Withheld, domains)
		}
		for i, row := range table.Rows {
			if row.Rank != i+1 || row.Bytes != wantBytes[i] {
				t.Fatalf("read %d rows[%d] = rank %d, %d bytes; want rank %d, %d bytes",
					read+1, i, row.Rank, row.Bytes, i+1, wantBytes[i])
			}
		}
	}
}

// TestFlowCollector_EntriesOmitWhatHasNoSeries pins absence. A table nobody
// enabled and a name nobody defined both report false, so the listing carries
// no key for either.
func TestFlowCollector_EntriesOmitWhatHasNoSeries(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	for _, name := range []string{"services", "tcp_flag", "", "exporters"} {
		if _, ok := c.Entries(name); ok {
			t.Errorf("Entries(%q) reported a table, want none", name)
		}
	}
	if _, ok := c.Entries("hosts"); !ok {
		t.Error(`Entries("hosts") reported no table, want the enabled one`)
	}
}

// TestFlowCollector_EntriesNameEveryTable pins the listing's vocabulary
// against the aggregator's own table names. A table added there without a
// branch here would answer 400 while its series carry its name.
func TestFlowCollector_EntriesNameEveryTable(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	modules := aggregator.Modules{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		TCPFlags: true, DSCP: true, ASNs: true, Applications: true,
		Countries: true, Threats: true, VLANs: true,
	}
	agg := aggregator.New(cfg, modules)

	var want []string
	for _, h := range agg.Health() {
		want = append(want, h.Aggregation)
	}
	got := slices.Clone(NewFlowCollector(agg, allCollectors(), cfg, nil, nil).Aggregations())

	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Aggregations() = %v, want the aggregator's tables %v", got, want)
	}
}

// TestFlowCollector_EntriesLabelRowsAsTheScrapeDoes pins the listing to the
// exposition. The names and the values come from the same pair the family
// descriptor was built from, so a row reads as the series it belongs to.
func TestFlowCollector_EntriesLabelRowsAsTheScrapeDoes(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{flowRecord("10.0.0.1", "10.0.0.9", 5000)})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	table, ok := c.Entries("hosts")
	if !ok {
		t.Fatal(`Entries("hosts") reported the table absent, want it read`)
	}
	if len(table.Rows) != 1 {
		t.Fatalf("rows = %d, want the one entry", len(table.Rows))
	}

	listed := map[string]string{}
	for i, name := range table.LabelNames {
		listed[name] = table.Rows[0].Labels[i]
	}

	if scraped := scrapedLabels(t, c); !sameLabels(listed, scraped) {
		t.Errorf("listing labels = %v, want the scrape's %v", listed, scraped)
	}
}

// scrapedLabels reads the one published host-pair series that is not the fold.
func scrapedLabels(t *testing.T, c prometheus.Collector) map[string]string {
	t.Helper()

	ch := make(chan prometheus.Metric, 64)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	labels := map[string]string{}
	for m := range ch {
		if !strings.Contains(m.Desc().String(), "xflow_host_pair_bytes_total") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		found := map[string]string{}
		for _, l := range pb.GetLabel() {
			found[l.GetName()] = l.GetValue()
		}
		if found["src"] == otherLabel {
			continue
		}
		labels = found
	}
	return labels
}

func sameLabels(a, b map[string]string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func allCollectors() config.Collectors {
	return config.Collectors{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		TCPFlags: true, DSCP: true, ASNs: true, Applications: true,
		Countries: true, Threats: true, VLANs: true,
	}
}

// TestFlowCollector_EntriesRankTheWithheldTail pins the listing's own order.
// A scrape orders a table only as far as its cut reaches, the entries past it
// being folded into one row, so the ranking of the tail is this route's to
// produce rather than something it inherits.
//
// The table is large enough that a partitioned tail is not an ordered one by
// chance, which a five-entry fixture cannot tell apart.
func TestFlowCollector_EntriesRankTheWithheldTail(t *testing.T) {
	t.Parallel()

	const entries = 64
	cfg := aggConfig()
	cfg.TopK = 5

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	records := make([]flow.Record, 0, entries)
	for i := range entries {
		records = append(records, flowRecord("10.0.0."+strconv.Itoa(i+1), "10.0.1.1", uint64(i+1)*10))
	}
	agg.Ingest(records)

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)
	table, ok := c.Entries("hosts")
	if !ok {
		t.Fatal(`Entries("hosts") reported the table absent, want it read`)
	}
	if len(table.Rows) != entries {
		t.Fatalf("rows = %d, want every entry listed", len(table.Rows))
	}

	for i := 1; i < len(table.Rows); i++ {
		if table.Rows[i].Bytes > table.Rows[i-1].Bytes {
			t.Fatalf("rows[%d].bytes = %d above rows[%d].bytes = %d, want the whole listing ranked",
				i, table.Rows[i].Bytes, i-1, table.Rows[i-1].Bytes)
		}
	}
}
