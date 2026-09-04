package collector

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/enrich"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

func aggConfig() config.Aggregation {
	return config.Aggregation{
		EntryTTL:   config.DefaultAggregationEntryTTL,
		MaxEntries: config.DefaultAggregationMaxEntries,
		TopK:       config.DefaultAggregationTopK,
		MinBytes:   config.DefaultAggregationMinBytes,
	}
}

func flowRecord(src, dst string, bytes uint64) flow.Record {
	return flow.Record{
		Exporter: netip.MustParseAddr("192.0.2.1"),
		Version:  flow.VersionNetFlowV9,
		SrcAddr:  netip.MustParseAddr(src),
		DstAddr:  netip.MustParseAddr(dst),
		DstPort:  443,
		Protocol: 6,
		Bytes:    bytes,
		Packets:  1,
		Flows:    1,
		InputIf:  3,
		OutputIf: 4,
	}
}

func TestFlowCollector_PublishesExportersAndHosts(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{Exporters: true, Hosts: true}
	agg := aggregator.New(aggConfig(), aggregator.Modules{Exporters: true, Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.2", 1000),
		flowRecord("10.0.0.1", "10.0.0.2", 500),
	})

	c := NewFlowCollector(agg, modules, aggConfig(), nil, nil)

	expected := `
# HELP xflow_exporter_bytes_total Sampling-corrected bytes per exporter and version, other carries the entry-bound fold
# TYPE xflow_exporter_bytes_total counter
xflow_exporter_bytes_total{exporter_address="192.0.2.1",version="netflow_v9"} 1500
xflow_exporter_bytes_total{exporter_address="other",version="other"} 0
# HELP xflow_host_pair_flows_total Flow records as exported per source-destination pair, other carries the entry-bound fold
# TYPE xflow_host_pair_flows_total counter
xflow_host_pair_flows_total{dst="10.0.0.2",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",src="10.0.0.1"} 2
xflow_host_pair_flows_total{dst="other",exporter_address="other",input_ifindex="other",output_ifindex="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_exporter_bytes_total", "xflow_host_pair_flows_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_TopKWithholdsTheLiveTail pins that entries below the cut
// are withheld rather than summed into other. Their totals are still moving,
// so adding them per scrape would make the other counter fall whenever one is
// evicted or grows into the cut.
func TestFlowCollector_TopKWithholdsTheLiveTail(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 2

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.9", 5000),
		flowRecord("10.0.0.2", "10.0.0.9", 3000),
		flowRecord("10.0.0.3", "10.0.0.9", 100),
		flowRecord("10.0.0.4", "10.0.0.9", 50),
	})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	expected := `
# HELP xflow_host_pair_bytes_total Sampling-corrected bytes per source-destination pair, other carries the entry-bound fold
# TYPE xflow_host_pair_bytes_total counter
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",src="10.0.0.1"} 5000
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",src="10.0.0.2"} 3000
xflow_host_pair_bytes_total{dst="other",exporter_address="other",input_ifindex="other",output_ifindex="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_host_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_MinBytesWithholdsMice pins the same contract for the byte
// threshold: a mouse flow keeps no series of its own and is not added to
// other while it lives.
func TestFlowCollector_MinBytesWithholdsMice(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.MinBytes = 1000

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.9", 5000),
		flowRecord("10.0.0.2", "10.0.0.9", 999),
	})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	expected := `
# HELP xflow_host_pair_bytes_total Sampling-corrected bytes per source-destination pair, other carries the entry-bound fold
# TYPE xflow_host_pair_bytes_total counter
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",src="10.0.0.1"} 5000
xflow_host_pair_bytes_total{dst="other",exporter_address="other",input_ifindex="other",output_ifindex="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_host_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_MinBytesAdmitsTheThresholdItself pins which side of the
// byte threshold is inclusive. At or above keeps its own series, so an entry
// reading exactly the threshold is published and the one byte below it is not.
func TestFlowCollector_MinBytesAdmitsTheThresholdItself(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.MinBytes = 1000

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.9", 1000),
		flowRecord("10.0.0.2", "10.0.0.9", 999),
	})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	expected := `
# HELP xflow_host_pair_bytes_total Sampling-corrected bytes per source-destination pair, other carries the entry-bound fold
# TYPE xflow_host_pair_bytes_total counter
xflow_host_pair_bytes_total{dst="10.0.0.9",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",src="10.0.0.1"} 1000
xflow_host_pair_bytes_total{dst="other",exporter_address="other",input_ifindex="other",output_ifindex="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_host_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestFlowCollector_ServiceAndASNAndApplicationLabels(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{Services: true, ASNs: true, Applications: true}
	agg := aggregator.New(aggConfig(),
		aggregator.Modules{Services: true, ASNs: true, Applications: true})

	r := flowRecord("10.0.0.1", "10.0.0.2", 700)
	r.SrcAS, r.DstAS = 64500, 64501
	r.AppName = "https"
	agg.Ingest([]flow.Record{r})

	c := NewFlowCollector(agg, modules, aggConfig(), nil, nil)

	expected := `
# HELP xflow_application_bytes_total Sampling-corrected bytes per application, other carries the entry-bound fold
# TYPE xflow_application_bytes_total counter
xflow_application_bytes_total{application="https",exporter_address="192.0.2.1"} 700
xflow_application_bytes_total{application="other",exporter_address="other"} 0
# HELP xflow_asn_pair_bytes_total Sampling-corrected bytes per AS pair, other carries the entry-bound fold
# TYPE xflow_asn_pair_bytes_total counter
xflow_asn_pair_bytes_total{dst_asn="64501",exporter_address="192.0.2.1",src_asn="64500"} 700
xflow_asn_pair_bytes_total{dst_asn="other",exporter_address="other",src_asn="other"} 0
# HELP xflow_service_bytes_total Sampling-corrected bytes per service five-tuple, other carries the entry-bound fold
# TYPE xflow_service_bytes_total counter
xflow_service_bytes_total{dst="10.0.0.2",exporter_address="192.0.2.1",input_ifindex="3",output_ifindex="4",port="443",proto="tcp",src="10.0.0.1"} 700
xflow_service_bytes_total{dst="other",exporter_address="other",input_ifindex="other",output_ifindex="other",port="other",proto="other",src="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_service_bytes_total", "xflow_asn_pair_bytes_total",
		"xflow_application_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestFlowCollector_HealthSeries(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{flowRecord("10.0.0.1", "10.0.0.2", 10)})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, aggConfig(), nil, nil)

	expected := `
# HELP xflow_aggregation_entries Entries held per aggregation table
# TYPE xflow_aggregation_entries gauge
xflow_aggregation_entries{aggregation="hosts"} 1
# HELP xflow_aggregation_evictions_total Idle entries evicted per aggregation table since process start
# TYPE xflow_aggregation_evictions_total counter
xflow_aggregation_evictions_total{aggregation="hosts"} 0
# HELP xflow_aggregation_overflow_records_total Records folded into other by the entry bound since process start
# TYPE xflow_aggregation_overflow_records_total counter
xflow_aggregation_overflow_records_total{aggregation="hosts"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_aggregation_entries", "xflow_aggregation_evictions_total",
		"xflow_aggregation_overflow_records_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestProtocolName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		protocol uint8
		want     string
	}{
		{1, "icmp"},
		{2, "igmp"},
		{4, "ipv4"},
		{6, "tcp"},
		{17, "udp"},
		{41, "ipv6"},
		{47, "gre"},
		{50, "esp"},
		{51, "ah"},
		{58, "icmpv6"},
		{88, "eigrp"},
		{89, "ospf"},
		{103, "pim"},
		{112, "vrrp"},
		{132, "sctp"},
		{200, "200"},
	}
	for _, tt := range tests {
		if got := protocolName(tt.protocol); got != tt.want {
			t.Errorf("protocolName(%d) = %q, want %q", tt.protocol, got, tt.want)
		}
	}
}

func TestDistributions_ObserveWithholdsAbsentDurations(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	d := c.RegisterDistributions()

	r := flowRecord("10.0.0.1", "10.0.0.2", 1500)
	r.SamplingRate = 10
	d.Observe([]flow.Record{r})

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	for _, family := range families {
		switch family.GetName() {
		case "xflow_flow_bytes":
			h := family.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() != 1 || h.GetSampleSum() != 15000 {
				t.Errorf("flow bytes histogram = count %d sum %v, want 1 and the corrected 15000",
					h.GetSampleCount(), h.GetSampleSum())
			}
		case "xflow_flow_duration_seconds":
			h := family.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() != 0 {
				t.Errorf("duration histogram count = %d, want 0 for a record with no instants",
					h.GetSampleCount())
			}
		}
	}
}

// TestFlowCollector_CountryPairs covers the family enrichment feeds, and the
// spelling of a side no database could place.
func TestFlowCollector_CountryPairs(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{Countries: true}
	agg := aggregator.New(aggConfig(), aggregator.Modules{Countries: true})

	placed := flowRecord("10.0.0.1", "10.0.0.2", 700)
	placed.SrcCountry, placed.DstCountry = "JP", "US"

	// A flow leaving a private network: the internal side belongs nowhere.
	partial := flowRecord("10.0.0.3", "10.0.0.4", 300)
	partial.DstCountry = "US"

	// Neither side placed: this one must feed no series at all.
	unplaced := flowRecord("10.0.0.5", "10.0.0.6", 900)

	agg.Ingest([]flow.Record{placed, partial, unplaced})

	c := NewFlowCollector(agg, modules, aggConfig(), nil, nil)

	expected := `
# HELP xflow_country_pair_bytes_total Sampling-corrected bytes per country pair, other carries the entry-bound fold
# TYPE xflow_country_pair_bytes_total counter
xflow_country_pair_bytes_total{dst_country="US",exporter_address="192.0.2.1",src_country="JP"} 700
xflow_country_pair_bytes_total{dst_country="US",exporter_address="192.0.2.1",src_country="unknown"} 300
xflow_country_pair_bytes_total{dst_country="other",exporter_address="other",src_country="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_country_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_DestinationLabels pins the label set and its order. The
// family carries no source: that is what separates it from the service
// five-tuple, and a source arriving here would make the two indistinguishable.
func TestFlowCollector_DestinationLabels(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{Destinations: true}
	agg := aggregator.New(aggConfig(), aggregator.Modules{Destinations: true})

	// Two sources reaching one service, which the family folds into one entry.
	agg.Ingest([]flow.Record{
		flowRecord("10.0.0.1", "10.0.0.2", 700),
		flowRecord("10.0.0.9", "10.0.0.2", 300),
	})

	c := NewFlowCollector(agg, modules, aggConfig(), nil, nil)

	expected := `
# HELP xflow_destination_bytes_total Sampling-corrected bytes per destination service, other carries the entry-bound fold
# TYPE xflow_destination_bytes_total counter
xflow_destination_bytes_total{dst="10.0.0.2",exporter_address="192.0.2.1",port="443",proto="tcp"} 1000
xflow_destination_bytes_total{dst="other",exporter_address="other",port="other",proto="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_destination_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestTCPFlagNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		flags uint8
		want  string
	}{
		{flags: 0x02, want: "syn"},
		{flags: 0x12, want: "syn,ack"},
		{flags: 0x18, want: "psh,ack"},
		{flags: 0x11, want: "fin,ack"},
		{flags: 0x04, want: "rst"},
		{flags: 0x1B, want: "fin,syn,psh,ack"},
		{flags: 0xC0, want: "ece,cwr"},
		{flags: 0x00, want: "none"},
	}

	for _, tt := range tests {
		if got := tcpFlagNames(tt.flags); got != tt.want {
			t.Errorf("tcpFlagNames(%#x) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestDSCPName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		dscp uint8
		want string
	}{
		{dscp: 0, want: "cs0"},
		{dscp: 46, want: "ef"},
		{dscp: 34, want: "af41"},
		{dscp: 24, want: "cs3"},
		{dscp: 44, want: "voice-admit"},
		{dscp: 1, want: "le"},
		{dscp: 45, want: "nqb"},
		// 2, 4 and 5 are the markings a stack reading the byte as RFC 791 did
		// still sets, and 7 and 63 are pool 2. The registry names none of
		// them, so none acquires a name invented here.
		{dscp: 2, want: "2"},
		{dscp: 4, want: "4"},
		{dscp: 5, want: "5"},
		{dscp: 7, want: "7"},
		{dscp: 63, want: "63"},
	}

	for _, tt := range tests {
		if got := dscpName(tt.dscp); got != tt.want {
			t.Errorf("dscpName(%d) = %q, want %q", tt.dscp, got, tt.want)
		}
	}
}

// TestFlowCollector_TCPFlagsAndDSCPLabels pins both label sets. The flags
// render as bits rather than as the byte, since 2 and 18 are a scan and a
// handshake and the numbers say so to nobody.
func TestFlowCollector_TCPFlagsAndDSCPLabels(t *testing.T) {
	t.Parallel()

	modules := config.Collectors{TCPFlags: true, DSCP: true}
	agg := aggregator.New(aggConfig(), aggregator.Modules{TCPFlags: true, DSCP: true})

	r := flowRecord("10.0.0.1", "10.0.0.2", 700)
	r.TCPFlags, r.TCPFlagsReported = 0x12, true
	r.TOS, r.TOSReported = 0xB8, true
	agg.Ingest([]flow.Record{r})

	c := NewFlowCollector(agg, modules, aggConfig(), nil, nil)

	expected := `
# HELP xflow_dscp_bytes_total Sampling-corrected bytes per DSCP class, other carries the entry-bound fold
# TYPE xflow_dscp_bytes_total counter
xflow_dscp_bytes_total{dscp="ef",exporter_address="192.0.2.1"} 700
xflow_dscp_bytes_total{dscp="other",exporter_address="other"} 0
# HELP xflow_tcp_flags_bytes_total Sampling-corrected bytes per TCP control-bit profile, other carries the entry-bound fold
# TYPE xflow_tcp_flags_bytes_total counter
xflow_tcp_flags_bytes_total{exporter_address="192.0.2.1",flags="syn,ack"} 700
xflow_tcp_flags_bytes_total{exporter_address="other",flags="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_tcp_flags_bytes_total", "xflow_dscp_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_TopKIsStableAcrossScrapes is the regression test for a
// series set that churned with nothing being ingested. Byte counts tie
// readily -- under sampling every single-packet minimum-size flow corrects to
// the same figure -- and a tie group straddling the Top-K cut admitted a
// different subset of itself on every scrape, so a long-term store billed
// series the exporter had not published twice in a row.
func TestFlowCollector_TopKIsStableAcrossScrapes(t *testing.T) {
	t.Parallel()

	const (
		topK  = 8
		tied  = 20
		bytes = 1280
	)

	cfg := aggConfig()
	cfg.TopK = topK
	cfg.MinBytes = 0

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	records := make([]flow.Record, 0, tied)
	for i := range tied {
		records = append(records, flowRecord("10.0.0.1", fmt.Sprintf("10.1.0.%d", i+1), bytes))
	}
	agg.Ingest(records)

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, nil)

	first := publishedHostPairs(t, c)
	if len(first) != topK {
		t.Fatalf("published %d series, want %d so the cut falls inside the tie group", len(first), topK)
	}

	for scrape := range 5 {
		got := publishedHostPairs(t, c)
		if !slices.Equal(first, got) {
			t.Errorf("scrape %d published %v, want %v unchanged with nothing ingested", scrape+2, got, first)
		}
	}
}

// publishedHostPairs collects the host-pair byte series and returns their
// destination labels in order, the fold series excluded.
func publishedHostPairs(t *testing.T, c prometheus.Collector) []string {
	t.Helper()

	ch := make(chan prometheus.Metric, 1024)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	var dsts []string
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if !strings.Contains(m.Desc().String(), "xflow_host_pair_bytes_total") {
			continue
		}
		for _, l := range pb.GetLabel() {
			if l.GetName() == "dst" && l.GetValue() != "other" {
				dsts = append(dsts, l.GetValue())
			}
		}
	}
	slices.Sort(dsts)
	return dsts
}

// TestFlowCollector_ASNNamesRideTheirOwnSeries pins where the organization
// goes. A database respelling a company must not break the counters it
// touches, so the name is published for the numbers the pair series carry and
// nowhere else.
func TestFlowCollector_ASNNamesRideTheirOwnSeries(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{ASNs: true})
	r := flowRecord("10.0.0.1", "10.0.0.2", 400)
	r.SrcAS, r.DstAS = 64500, 64501
	agg.Ingest([]flow.Record{r})

	names := func(as uint32) (string, bool) {
		if as == 64500 {
			return "Example Networks", true
		}
		return "", false
	}
	c := NewFlowCollector(agg, config.Collectors{ASNs: true}, aggConfig(), names, nil)

	expected := `
# HELP xflow_asn_info Always 1, carrying what a database calls each AS the pair table publishes
# TYPE xflow_asn_info gauge
xflow_asn_info{asn="64500",organization="Example Networks"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "xflow_asn_info"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_ASNNamesFollowTheTopKCut pins the naming series to the cut
// the pair series take, rather than to the table behind it. The table runs to
// --aggregation.max-entries and a database names every AS there is, so reading
// it whole would publish a name for every AS below the cut -- each one a
// series with nothing to join to, and the family orders of magnitude past the
// one it describes. Both families are asserted because the property is a
// join: what the numbers are matters only against the pairs carrying them.
func TestFlowCollector_ASNNamesFollowTheTopKCut(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 1

	agg := aggregator.New(cfg, aggregator.Modules{ASNs: true})
	records := make([]flow.Record, 0, 8)
	for i := range 8 {
		r := flowRecord(fmt.Sprintf("10.0.%d.1", i), fmt.Sprintf("10.1.%d.2", i), uint64(100+i))
		r.SrcAS, r.DstAS = uint32(64500+i*2), uint32(64501+i*2)
		records = append(records, r)
	}
	agg.Ingest(records)

	names := func(as uint32) (string, bool) { return fmt.Sprintf("AS %d", as), true }
	c := NewFlowCollector(agg, config.Collectors{ASNs: true}, cfg, names, nil)

	// The heaviest pair is the last ingested, and it is the only one published.
	expected := `
# HELP xflow_asn_info Always 1, carrying what a database calls each AS the pair table publishes
# TYPE xflow_asn_info gauge
xflow_asn_info{asn="64514",organization="AS 64514"} 1
xflow_asn_info{asn="64515",organization="AS 64515"} 1
# HELP xflow_asn_pair_bytes_total Sampling-corrected bytes per AS pair, other carries the entry-bound fold
# TYPE xflow_asn_pair_bytes_total counter
xflow_asn_pair_bytes_total{dst_asn="64515",exporter_address="192.0.2.1",src_asn="64514"} 107
xflow_asn_pair_bytes_total{dst_asn="other",exporter_address="other",src_asn="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_asn_info", "xflow_asn_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_ASNNamesReadTheSnapshotThePairsCameFrom is the regression
// test for a name published for a pair that was not. The table moves while a
// scrape runs -- the receiver goroutines ingest throughout it -- so a second
// read of the source answers with a table the pair series never saw, and the
// cut taken from it can name an AS no published pair carries.
func TestFlowCollector_ASNNamesReadTheSnapshotThePairsCameFrom(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 1

	exporter := netip.MustParseAddr("192.0.2.1")
	pair := aggregator.EntrySnapshot[aggregator.ASNKey]{
		Key:    aggregator.ASNKey{Exporter: exporter, SrcAS: 64500, DstAS: 64501},
		Totals: aggregator.Totals{Bytes: 5000, Packets: 5, Flows: 1},
	}
	// The same table one ingest later, with a heavier pair holding the only
	// slot the cut has.
	usurper := aggregator.EntrySnapshot[aggregator.ASNKey]{
		Key:    aggregator.ASNKey{Exporter: exporter, SrcAS: 64600, DstAS: 64601},
		Totals: aggregator.Totals{Bytes: 9000, Packets: 9, Flows: 1},
	}

	src := &movingASNs{reads: [][]aggregator.EntrySnapshot[aggregator.ASNKey]{
		{pair},
		{usurper, pair},
	}}

	names := func(as uint32) (string, bool) { return fmt.Sprintf("AS %d", as), true }
	c := NewFlowCollector(src, config.Collectors{ASNs: true}, cfg, names, nil)

	expected := `
# HELP xflow_asn_info Always 1, carrying what a database calls each AS the pair table publishes
# TYPE xflow_asn_info gauge
xflow_asn_info{asn="64500",organization="AS 64500"} 1
xflow_asn_info{asn="64501",organization="AS 64501"} 1
# HELP xflow_asn_pair_bytes_total Sampling-corrected bytes per AS pair, other carries the entry-bound fold
# TYPE xflow_asn_pair_bytes_total counter
xflow_asn_pair_bytes_total{dst_asn="64501",exporter_address="192.0.2.1",src_asn="64500"} 5000
xflow_asn_pair_bytes_total{dst_asn="other",exporter_address="other",src_asn="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_asn_info", "xflow_asn_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
	// The property is one read per scrape, not the shape of the stub: a stub
	// that stopped moving would leave the assertion above passing over the
	// defect it exists to catch.
	if src.taken != 1 {
		t.Errorf("source read %d times in one scrape, want 1", src.taken)
	}
}

// TestFlowCollector_ASNNamesFollowTheByteThreshold pins the naming series to
// the whole cut rather than to its Top-K half. --aggregation.min-bytes
// withholds a pair as surely as the rank does, and a name published for one it
// withheld would have nothing to join to.
func TestFlowCollector_ASNNamesFollowTheByteThreshold(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.MinBytes = 1000

	agg := aggregator.New(cfg, aggregator.Modules{ASNs: true})
	heavy := flowRecord("10.0.0.1", "10.0.0.2", 5000)
	heavy.SrcAS, heavy.DstAS = 64500, 64501
	mouse := flowRecord("10.0.0.3", "10.0.0.4", 999)
	mouse.SrcAS, mouse.DstAS = 64600, 64601
	agg.Ingest([]flow.Record{heavy, mouse})

	names := func(as uint32) (string, bool) { return fmt.Sprintf("AS %d", as), true }
	c := NewFlowCollector(agg, config.Collectors{ASNs: true}, cfg, names, nil)

	expected := `
# HELP xflow_asn_info Always 1, carrying what a database calls each AS the pair table publishes
# TYPE xflow_asn_info gauge
xflow_asn_info{asn="64500",organization="AS 64500"} 1
xflow_asn_info{asn="64501",organization="AS 64501"} 1
# HELP xflow_asn_pair_bytes_total Sampling-corrected bytes per AS pair, other carries the entry-bound fold
# TYPE xflow_asn_pair_bytes_total counter
xflow_asn_pair_bytes_total{dst_asn="64501",exporter_address="192.0.2.1",src_asn="64500"} 5000
xflow_asn_pair_bytes_total{dst_asn="other",exporter_address="other",src_asn="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_asn_info", "xflow_asn_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_ASNNameNoLabelCanHoldCostsItsOwnSeries pins what a
// database string Prometheus refuses costs. An mmdb file is not validated for
// UTF-8 when it is read, so the bytes reaching the label are the file's: they
// cost the name its series and leave the pair counters, and every family
// behind them, on the scrape.
func TestFlowCollector_ASNNameNoLabelCanHoldCostsItsOwnSeries(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{ASNs: true})
	r := flowRecord("10.0.0.1", "10.0.0.2", 400)
	r.SrcAS, r.DstAS = 64500, 64501
	agg.Ingest([]flow.Record{r})

	names := func(as uint32) (string, bool) {
		if as == 64500 {
			return "Example\xffNetworks", true
		}
		return "Example Peering", true
	}
	c := NewFlowCollector(agg, config.Collectors{ASNs: true}, aggConfig(), names, nil)

	expected := `
# HELP xflow_asn_info Always 1, carrying what a database calls each AS the pair table publishes
# TYPE xflow_asn_info gauge
xflow_asn_info{asn="64501",organization="Example Peering"} 1
# HELP xflow_asn_pair_bytes_total Sampling-corrected bytes per AS pair, other carries the entry-bound fold
# TYPE xflow_asn_pair_bytes_total counter
xflow_asn_pair_bytes_total{dst_asn="64501",exporter_address="192.0.2.1",src_asn="64500"} 400
xflow_asn_pair_bytes_total{dst_asn="other",exporter_address="other",src_asn="other"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_asn_info", "xflow_asn_pair_bytes_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// movingASNs answers each AS-pair read with the next table in reads, the last
// one standing for every read past it. Each answer is a copy, since a caller
// sorts what it is given. Every other aggregation stays empty.
type movingASNs struct {
	reads [][]aggregator.EntrySnapshot[aggregator.ASNKey]
	taken int
}

func (m *movingASNs) ASNs() ([]aggregator.EntrySnapshot[aggregator.ASNKey], aggregator.Totals) {
	entries := m.reads[min(m.taken, len(m.reads)-1)]
	m.taken++
	return slices.Clone(entries), aggregator.Totals{}
}

func (m *movingASNs) Exporters() ([]aggregator.EntrySnapshot[aggregator.ExporterKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Hosts() ([]aggregator.EntrySnapshot[aggregator.HostKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Services() ([]aggregator.EntrySnapshot[aggregator.ServiceKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Destinations() ([]aggregator.EntrySnapshot[aggregator.DestinationKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) TCPFlags() ([]aggregator.EntrySnapshot[aggregator.TCPFlagsKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) DSCP() ([]aggregator.EntrySnapshot[aggregator.DSCPKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Applications() ([]aggregator.EntrySnapshot[aggregator.AppKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Countries() ([]aggregator.EntrySnapshot[aggregator.CountryKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Threats() ([]aggregator.EntrySnapshot[aggregator.ThreatKey], aggregator.Totals) {
	return nil, aggregator.Totals{}
}

func (m *movingASNs) Health() []aggregator.TableHealth { return nil }

// TestFlowCollector_ASNNamesAbsentWithoutADatabase pins the other half: with
// no database to ask, the naming series is absent rather than empty.
func TestFlowCollector_ASNNamesAbsentWithoutADatabase(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{ASNs: true})
	r := flowRecord("10.0.0.1", "10.0.0.2", 400)
	r.SrcAS, r.DstAS = 64500, 64501
	agg.Ingest([]flow.Record{r})

	c := NewFlowCollector(agg, config.Collectors{ASNs: true}, aggConfig(), nil, nil)
	if got := testutil.CollectAndCount(c, "xflow_asn_info"); got != 0 {
		t.Errorf("xflow_asn_info series = %d, want none without a database", got)
	}
}

// TestFlowCollector_ASNNamesSkipZero pins that the reserved number is never
// named. AS 0 means no AS, and a database asked about it would be answering
// about nothing.
func TestFlowCollector_ASNNamesSkipZero(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{ASNs: true})
	r := flowRecord("10.0.0.1", "10.0.0.2", 400)
	r.SrcAS, r.DstAS = 0, 64500
	agg.Ingest([]flow.Record{r})

	names := func(uint32) (string, bool) { return "Example Networks", true }
	c := NewFlowCollector(agg, config.Collectors{ASNs: true}, aggConfig(), names, nil)

	expected := `
# HELP xflow_asn_info Always 1, carrying what a database calls each AS the pair table publishes
# TYPE xflow_asn_info gauge
xflow_asn_info{asn="64500",organization="Example Networks"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "xflow_asn_info"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// mappingNames loads one mapping document and returns the collector's reader
// of it, so the tests below go through the parse the exporter really runs.
func mappingNames(t *testing.T, document string) func() *enrich.NameSet {
	t.Helper()

	path := filepath.Join(t.TempDir(), "mapping.yml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}
	m, err := enrich.NewMapping(path)
	if err != nil {
		t.Fatalf("NewMapping() error = %v, want nil", err)
	}
	return m.Names
}

// TestFlowCollector_NamesRideTheirOwnSeries pins where a looked-up name goes.
// It rides a series of its own rather than the counters' labels, because an
// operator respelling a hostname would otherwise break every counter under
// that device: the pair table would open a new entry for the new spelling and
// rate() would read the old one as gone.
//
// The three absences are the same rule from the other side. A port the file
// does not name, a port no published entry crossed, and a device carrying
// interfaces but no hostname each produce no row, which a join shows by
// finding nothing to join to.
func TestFlowCollector_NamesRideTheirOwnSeries(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{flowRecord("10.0.0.1", "10.0.0.2", 1000)})

	// The fixture crosses 3 and 4 on 192.0.2.1: 4 is unnamed, 99 is named
	// but crossed by nothing, and 192.0.2.9 names no hostname at all.
	names := mappingNames(t, `devices:
  192.0.2.1:
    hostname: sw1.example.net
    interfaces:
      3: Gi0/3
      99: Gi0/99
  192.0.2.9:
    interfaces:
      1: Vl1
`)
	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, aggConfig(), nil, names)

	expected := `
# HELP xflow_device_info Always 1, carrying what the mapping file calls each device it names
# TYPE xflow_device_info gauge
xflow_device_info{exporter_address="192.0.2.1",exporter_name="sw1.example.net"} 1
# HELP xflow_interface_info Always 1, carrying what the mapping file calls each interface the tables publish
# TYPE xflow_interface_info gauge
xflow_interface_info{exporter_address="192.0.2.1",ifindex="3",ifname="Gi0/3"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_device_info", "xflow_interface_info"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_InterfaceNamesFollowTheTopKCut pins the bound on the
// interface series. The counters a name joins to are the published ones, so a
// port whose only entries fell below the cut has nothing to name, and naming
// it anyway would publish a row for traffic no counter carries.
func TestFlowCollector_InterfaceNamesFollowTheTopKCut(t *testing.T) {
	t.Parallel()

	cfg := aggConfig()
	cfg.TopK = 1

	heavy := flowRecord("10.0.0.1", "10.0.0.9", 5000)
	mouse := flowRecord("10.0.0.2", "10.0.0.9", 10)
	mouse.InputIf = 7

	agg := aggregator.New(cfg, aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{heavy, mouse})

	names := mappingNames(t, "devices:\n  192.0.2.1:\n    interfaces:\n      3: Gi0/3\n      7: Gi0/7\n")
	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, cfg, nil, names)

	expected := `
# HELP xflow_interface_info Always 1, carrying what the mapping file calls each interface the tables publish
# TYPE xflow_interface_info gauge
xflow_interface_info{exporter_address="192.0.2.1",ifindex="3",ifname="Gi0/3"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_interface_info"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// TestFlowCollector_NamesAbsentWithoutAMappingFile pins that neither naming
// series exists at all without one, rather than existing and holding nothing:
// an empty family reads as a fleet nobody named, where absence reads as a
// feature nobody turned on.
func TestFlowCollector_NamesAbsentWithoutAMappingFile(t *testing.T) {
	t.Parallel()

	agg := aggregator.New(aggConfig(), aggregator.Modules{Hosts: true})
	agg.Ingest([]flow.Record{flowRecord("10.0.0.1", "10.0.0.2", 1000)})

	c := NewFlowCollector(agg, config.Collectors{Hosts: true}, aggConfig(), nil, nil)

	if err := testutil.CollectAndCompare(c, strings.NewReader(""),
		"xflow_device_info", "xflow_interface_info"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}
