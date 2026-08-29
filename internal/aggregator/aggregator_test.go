package aggregator

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

var (
	testExporter = netip.MustParseAddr("192.0.2.1")
	testSrc      = netip.MustParseAddr("10.0.0.1")
	testDst      = netip.MustParseAddr("198.51.100.7")
)

func testConfig() config.Aggregation {
	return config.Aggregation{
		EntryTTL:   config.DefaultAggregationEntryTTL,
		MaxEntries: config.DefaultAggregationMaxEntries,
		TopK:       config.DefaultAggregationTopK,
		MinBytes:   config.DefaultAggregationMinBytes,
	}
}

func allModules() Modules {
	return Modules{
		Exporters: true, Hosts: true, Services: true, Destinations: true,
		ASNs: true, Applications: true,
	}
}

// testRecord is a fully-dimensioned record.
func testRecord() flow.Record {
	return flow.Record{
		Exporter: testExporter,
		Version:  flow.VersionNetFlowV9,
		SrcAddr:  testSrc,
		DstAddr:  testDst,
		SrcPort:  51234,
		DstPort:  443,
		Protocol: 6,
		Bytes:    1000,
		Packets:  10,
		Flows:    1,
		SrcAS:    64500,
		DstAS:    64501,
		AppName:  "https",
	}
}

func TestAggregator_IngestFeedsEveryEnabledTable(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), allModules())
	a.Ingest([]flow.Record{testRecord(), testRecord()})

	exporters, _ := a.Exporters()
	if len(exporters) != 1 || exporters[0].Bytes != 2000 || exporters[0].Flows != 2 {
		t.Errorf("Exporters() = %+v, want one entry with 2000 bytes and 2 flows", exporters)
	}
	if key := exporters[0].Key; key.Exporter != testExporter || key.Version != flow.VersionNetFlowV9 {
		t.Errorf("exporter key = %+v, want device and version", key)
	}

	hosts, _ := a.Hosts()
	if len(hosts) != 1 || hosts[0].Key.Src != testSrc || hosts[0].Packets != 20 {
		t.Errorf("Hosts() = %+v, want one src-dst entry with 20 packets", hosts)
	}

	services, _ := a.Services()
	if len(services) != 1 || services[0].Key.Port != 443 || services[0].Key.Protocol != 6 {
		t.Errorf("Services() = %+v, want one entry keyed by dst port and protocol", services)
	}

	asns, _ := a.ASNs()
	if len(asns) != 1 || asns[0].Key.SrcAS != 64500 || asns[0].Key.DstAS != 64501 {
		t.Errorf("ASNs() = %+v, want one AS-pair entry", asns)
	}

	apps, _ := a.Applications()
	if len(apps) != 1 || apps[0].Key.Name != "https" {
		t.Errorf("Applications() = %+v, want one https entry", apps)
	}
}

func TestAggregator_SamplingCorrectionScalesBytesAndPackets(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{Exporters: true})

	r := testRecord()
	r.SamplingRate = 1000
	a.Ingest([]flow.Record{r})

	exporters, _ := a.Exporters()
	if len(exporters) != 1 {
		t.Fatalf("Exporters() returned %d entries, want 1", len(exporters))
	}
	if exporters[0].Bytes != 1_000_000 || exporters[0].Packets != 10_000 {
		t.Errorf("entry = %+v, want bytes and packets multiplied by the rate", exporters[0])
	}
	if exporters[0].Flows != 1 {
		t.Errorf("Flows = %d, want the flow count left as exported", exporters[0].Flows)
	}
}

func TestAggregator_AbsentDimensionsFeedNoTable(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), allModules())

	// A NetFlow v8 AS aggregate: counters and AS numbers, no addresses, no
	// protocol, no application.
	a.Ingest([]flow.Record{{
		Exporter: testExporter,
		Version:  flow.VersionNetFlowV8,
		Bytes:    500,
		Packets:  5,
		Flows:    3,
		SrcAS:    64500,
		DstAS:    64501,
	}})

	if hosts, _ := a.Hosts(); len(hosts) != 0 {
		t.Errorf("Hosts() = %+v, want no entry keyed by fabricated zero addresses", hosts)
	}
	if services, _ := a.Services(); len(services) != 0 {
		t.Errorf("Services() = %+v, want no entry", services)
	}
	if apps, _ := a.Applications(); len(apps) != 0 {
		t.Errorf("Applications() = %+v, want no entry", apps)
	}
	if asns, _ := a.ASNs(); len(asns) != 1 {
		t.Errorf("ASNs() = %+v, want the one dimension the record carried", asns)
	}
	if exporters, _ := a.Exporters(); len(exporters) != 1 || exporters[0].Flows != 3 {
		t.Errorf("Exporters() = %+v, want the aggregate flow count kept", exporters)
	}
}

func TestAggregator_NumberedApplicationFallback(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{Applications: true})

	r := testRecord()
	r.AppName = ""
	r.AppID = 13<<24 | 42
	a.Ingest([]flow.Record{r})

	apps, _ := a.Applications()
	if len(apps) != 1 || apps[0].Key.Name != "13:42" {
		t.Errorf("Applications() = %+v, want the engine:selector fallback 13:42", apps)
	}
}

func TestAggregator_CapacityFoldsIntoOverflow(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.MaxEntries = 2
	a := New(cfg, Modules{Hosts: true})

	for i := range 5 {
		r := testRecord()
		r.SrcAddr = netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		a.Ingest([]flow.Record{r})
	}

	hosts, overflow := a.Hosts()
	if len(hosts) != 2 {
		t.Errorf("Hosts() holds %d entries, want the bound of 2", len(hosts))
	}
	if overflow.Bytes != 3000 || overflow.Flows != 3 {
		t.Errorf("overflow = %+v, want the three rejected records folded in", overflow)
	}

	health := a.Health()
	if len(health) != 1 || health[0].CapacityFolds != 3 {
		t.Errorf("Health() = %+v, want 3 capacity folds", health)
	}
}

func TestAggregator_SweepEvictsIdleEntries(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.EntryTTL = time.Minute
	a := New(cfg, Modules{Hosts: true})

	now := time.Unix(1_756_500_000, 0)
	a.now = func() time.Time { return now }

	a.Ingest([]flow.Record{testRecord()})

	// A second entry arrives later and must survive the sweep.
	now = now.Add(50 * time.Second)
	fresh := testRecord()
	fresh.SrcAddr = netip.MustParseAddr("10.0.0.99")
	a.Ingest([]flow.Record{fresh})

	// The first entry is now 70 seconds idle, past the minute TTL.
	now = now.Add(20 * time.Second)
	a.sweep()

	hosts, _ := a.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("Hosts() holds %d entries after the sweep, want 1", len(hosts))
	}
	if hosts[0].Key.Src != fresh.SrcAddr {
		t.Errorf("surviving entry = %+v, want the fresh one", hosts[0].Key)
	}

	health := a.Health()
	if health[0].IdleEvictions != 1 {
		t.Errorf("IdleEvictions = %d, want 1", health[0].IdleEvictions)
	}
}

func TestAggregator_RunSweepsUntilCanceled(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.EntryTTL = time.Second
	a := New(cfg, Modules{Hosts: true})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestAggregator_DisabledModulesReturnNothing(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{})
	a.Ingest([]flow.Record{testRecord()})

	if entries, _ := a.Exporters(); entries != nil {
		t.Errorf("Exporters() = %+v, want nil with the module disabled", entries)
	}
	if entries, _ := a.Destinations(); entries != nil {
		t.Errorf("Destinations() = %+v, want nil with the module disabled", entries)
	}
	if got := len(a.Health()); got != 0 {
		t.Errorf("Health() reports %d tables, want 0", got)
	}
	if (Modules{}).Any() {
		t.Error("Any() = true for no modules, want false")
	}
	if !allModules().Any() {
		t.Error("Any() = false with modules enabled, want true")
	}
}

func BenchmarkAggregator_Ingest(b *testing.B) {
	a := New(testConfig(), allModules())
	records := make([]flow.Record, 30)
	for i := range records {
		records[i] = testRecord()
		records[i].SrcPort = uint16(50000 + i)
	}
	a.Ingest(records) // warm the entries

	b.ReportAllocs()
	for b.Loop() {
		a.Ingest(records)
	}
}

// TestAggregator_ThreatsKeepTheSideTheHitWasSeenOn pins the dimension the
// flagged-address table exists for. A hit on the source is an outside address
// probing the perimeter, and a hit on the destination is an inside host that
// reached a listed one -- the two read as different events, so the side has to
// survive into the key rather than being folded into one address series.
func TestAggregator_ThreatsKeepTheSideTheHitWasSeenOn(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{Threats: true})

	src := testRecord()
	src.SrcFlagged = true

	dst := testRecord()
	dst.DstFlagged = true
	dst.Bytes = 2000

	a.Ingest([]flow.Record{src, dst})

	entries, _ := a.Threats()
	if len(entries) != 2 {
		t.Fatalf("Threats() = %d entries, want one per side", len(entries))
	}

	seen := make(map[string]ThreatKey, len(entries))
	for _, e := range entries {
		seen[e.Key.Direction] = e.Key
	}

	if key, ok := seen[DirectionSrc]; !ok || key.Address != testSrc {
		t.Errorf("source-side entry = %+v, want the source address keyed as src", key)
	}
	if key, ok := seen[DirectionDst]; !ok || key.Address != testDst {
		t.Errorf("destination-side entry = %+v, want the destination address keyed as dst", key)
	}
}

// TestAggregator_UnflaggedRecordsFeedNoThreatTable pins the absence rule for
// the module: an address no list covers is uncovered rather than clean, so it
// must produce no series at all.
func TestAggregator_UnflaggedRecordsFeedNoThreatTable(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{Threats: true})
	a.Ingest([]flow.Record{testRecord()})

	if entries, _ := a.Threats(); len(entries) != 0 {
		t.Errorf("Threats() = %d entries for an unflagged record, want none", len(entries))
	}
}

// TestAggregator_DestinationsFoldEverySourceIntoOne pins what separates this
// table from the service table: it is the same key without the source, so
// every host that reached one service shares an entry where the service table
// keeps one apiece. The reading is what the service received, not who sent it.
func TestAggregator_DestinationsFoldEverySourceIntoOne(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{Services: true, Destinations: true})

	for _, src := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		r := testRecord()
		r.SrcAddr = netip.MustParseAddr(src)
		a.Ingest([]flow.Record{r})
	}

	if services, _ := a.Services(); len(services) != 3 {
		t.Errorf("Services() returned %d entries, want one per source", len(services))
	}

	destinations, fold := a.Destinations()
	if len(destinations) != 1 {
		t.Fatalf("Destinations() returned %d entries, want the three sources in one", len(destinations))
	}

	got := destinations[0]
	if got.Bytes != 3000 || got.Packets != 30 || got.Flows != 3 {
		t.Errorf("Destinations() totals = %+v, want every source summed", got.Totals)
	}
	if got.Key.Dst != testDst || got.Key.Protocol != 6 || got.Key.Port != 443 {
		t.Errorf("destination key = %+v, want the service the records reached", got.Key)
	}
	if fold != (Totals{}) {
		t.Errorf("fold = %+v, want nothing folded below the entry bound", fold)
	}
}

// TestAggregator_DestinationsNeedADestinationAndAProtocol pins the two
// conditions the table checks and the one it deliberately does not. A record
// whose source never resolved still names the service it reached, so the
// source is not among them; one naming no destination, or carrying no
// protocol, would key a series on a value the device never reported.
func TestAggregator_DestinationsNeedADestinationAndAProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*flow.Record)
		want   int
	}{
		{
			name:   "no source resolved",
			mutate: func(r *flow.Record) { r.SrcAddr = netip.Addr{} },
			want:   1,
		},
		{
			name:   "no destination",
			mutate: func(r *flow.Record) { r.DstAddr = netip.Addr{} },
			want:   0,
		},
		{
			name:   "no protocol",
			mutate: func(r *flow.Record) { r.Protocol = 0 },
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := New(testConfig(), Modules{Destinations: true})
			r := testRecord()
			tt.mutate(&r)
			a.Ingest([]flow.Record{r})

			entries, _ := a.Destinations()
			if len(entries) != tt.want {
				t.Errorf("Destinations() returned %d entries, want %d", len(entries), tt.want)
			}
		})
	}
}

// TestAggregator_TCPFlagsKeyOnReportedNotOnValue pins the two conditions.
// Admission asks whether the device reported the control bits, not what they
// were: a TCP segment setting none is a NULL scan, which is exactly what a
// control-bit breakdown exists to surface, while a device that exports no
// such field must not be given a series saying it measured nothing. A record
// of another protocol has no control bits to report at all.
func TestAggregator_TCPFlagsKeyOnReportedNotOnValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol uint8
		flags    uint8
		reported bool
		want     int
	}{
		{name: "tcp with bits", protocol: 6, flags: 0x12, reported: true, want: 1},
		{name: "tcp setting none", protocol: 6, flags: 0, reported: true, want: 1},
		{name: "tcp the device did not report", protocol: 6, flags: 0, reported: false, want: 0},
		{name: "udp", protocol: 17, flags: 0, reported: false, want: 0},
		{name: "udp carrying bits", protocol: 17, flags: 0x12, reported: true, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := New(testConfig(), Modules{TCPFlags: true})
			r := testRecord()
			r.Protocol, r.TCPFlags, r.TCPFlagsReported = tt.protocol, tt.flags, tt.reported
			a.Ingest([]flow.Record{r})

			entries, _ := a.TCPFlags()
			if len(entries) != tt.want {
				t.Fatalf("TCPFlags() returned %d entries, want %d", len(entries), tt.want)
			}
			if tt.want == 1 && entries[0].Key.Flags != tt.flags {
				t.Errorf("flags = %#x, want %#x", entries[0].Key.Flags, tt.flags)
			}
		})
	}
}

// TestAggregator_DSCPKeysOnReportedNotOnValue pins what separates this table
// from every other: zero is a value here. Best-effort traffic marks nothing,
// so keying admission on the byte would drop the majority of a network and
// keying it on nothing would invent a class for every device that exports no
// TOS at all.
func TestAggregator_DSCPKeysOnReportedNotOnValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tos      uint8
		reported bool
		want     int
		wantDSCP uint8
	}{
		{name: "best effort, reported", tos: 0, reported: true, want: 1, wantDSCP: 0},
		{name: "expedited forwarding", tos: 0xB8, reported: true, want: 1, wantDSCP: 46},
		{name: "not reported", tos: 0, reported: false, want: 0},
		{name: "not reported but non-zero", tos: 0xB8, reported: false, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := New(testConfig(), Modules{DSCP: true})
			r := testRecord()
			r.TOS, r.TOSReported = tt.tos, tt.reported
			a.Ingest([]flow.Record{r})

			entries, _ := a.DSCP()
			if len(entries) != tt.want {
				t.Fatalf("DSCP() returned %d entries, want %d", len(entries), tt.want)
			}
			if tt.want == 1 && entries[0].Key.DSCP != tt.wantDSCP {
				t.Errorf("DSCP = %d, want %d: the two low bits are ECN, not a class",
					entries[0].Key.DSCP, tt.wantDSCP)
			}
		})
	}
}
