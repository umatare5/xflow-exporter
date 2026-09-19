package aggregator

import (
	"context"
	"math"
	"net/netip"
	"reflect"
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
		TCPFlags: true, DSCP: true, ASNs: true, Applications: true,
		Countries: true, Threats: true, VLANs: true,
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

	// A template collecting the AS pair and its counters alone: no addresses,
	// no protocol, no application.
	a.Ingest([]flow.Record{{
		Exporter: testExporter,
		Version:  flow.VersionNetFlowV9,
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
		t.Errorf("Exporters() = %+v, want the flow count kept", exporters)
	}
}

// TestAggregator_VLANsAdmitASideAtATime pins what opens a VLAN entry. Traffic
// between a mapped segment and the internet resolves on one side only and is
// the case the table exists for, where a record the file placed on neither
// side is absence rather than a pair of segments numbered zero.
func TestAggregator_VLANsAdmitASideAtATime(t *testing.T) {
	t.Parallel()

	both := testRecord()
	both.SrcVLAN, both.DstVLAN = 800, 801

	srcOnly := testRecord()
	srcOnly.SrcVLAN = 800

	dstOnly := testRecord()
	dstOnly.DstVLAN = 801

	a := New(testConfig(), allModules())
	a.Ingest([]flow.Record{both, srcOnly, dstOnly, testRecord()})

	vlans, _ := a.VLANs()
	keys := make(map[VLANKey]struct{}, len(vlans))
	for _, e := range vlans {
		keys[e.Key] = struct{}{}
	}

	for _, want := range []VLANKey{
		{Exporter: testExporter, Src: 800, Dst: 801},
		{Exporter: testExporter, Src: 800},
		{Exporter: testExporter, Dst: 801},
	} {
		if _, held := keys[want]; !held {
			t.Errorf("VLANs() holds no entry for %+v", want)
		}
	}
	if len(vlans) != len(keys) || len(keys) != 3 {
		t.Errorf("VLANs() = %d entries, want 3: the unmapped record must open none", len(vlans))
	}
}

// TestAggregator_AnAggregateFeedsItsDomainAlone pins the v8 gate. A device
// running ten aggregation caches hands the same traffic over ten times, so a
// derived table fed from them counts one flow once per cache while the domain
// they arrived in still separates the readings.
func TestAggregator_AnAggregateFeedsItsDomainAlone(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), allModules())

	a.Ingest([]flow.Record{{
		Exporter:         testExporter,
		Version:          flow.VersionNetFlowV8,
		ODID:             5,
		SrcAddr:          netip.MustParseAddr("10.0.0.0"),
		DstAddr:          netip.MustParseAddr("10.0.1.0"),
		Protocol:         6,
		DstPort:          443,
		TOSReported:      true,
		TCPFlags:         2,
		TCPFlagsReported: true,
		SrcAS:            64500,
		SrcVLAN:          800,
		Bytes:            500,
		Packets:          5,
		Flows:            3,
	}})

	for name, entries := range map[string]int{
		"hosts": lengthOf(a.Hosts()), "services": lengthOf(a.Services()),
		"destinations": lengthOf(a.Destinations()), "dscp": lengthOf(a.DSCP()),
		"asns": lengthOf(a.ASNs()), "tcp_flags": lengthOf(a.TCPFlags()),
		"vlans": lengthOf(a.VLANs()),
	} {
		if entries != 0 {
			t.Errorf("%s = %d entries, want none from an aggregate", name, entries)
		}
	}

	exporters, _ := a.Exporters()
	if len(exporters) != 1 || exporters[0].Key.ODID != 5 || exporters[0].Flows != 3 {
		t.Errorf("Exporters() = %+v, want the aggregate kept under its own method", exporters)
	}
}

// lengthOf drops the overflow totals a table snapshot returns beside its
// entries, which these assertions do not read.
func lengthOf[K comparable](entries []EntrySnapshot[K], _ Totals) int {
	return len(entries)
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

// TestAggregator_AnyReportsEveryModuleOnItsOwn pins what Any decides: the
// tables and the collector over them are built only where it reports true, so
// a module missing from it accepts its flag, enables nothing and publishes no
// series at all. No other test sees that, each of them turning several
// modules on at once. The fields are walked rather than listed so a module
// added later cannot be left out of the walk itself.
func TestAggregator_AnyReportsEveryModuleOnItsOwn(t *testing.T) {
	t.Parallel()

	fields := reflect.TypeOf(Modules{})
	for i := range fields.NumField() {
		one := Modules{}
		reflect.ValueOf(&one).Elem().Field(i).SetBool(true)

		if !one.Any() {
			t.Errorf("Any() = false with %s alone, want true", fields.Field(i).Name)
		}
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

	seen := make(map[Side]ThreatKey, len(entries))
	for _, e := range entries {
		seen[e.Key.Side] = e.Key
	}

	if key, ok := seen[SideSrc]; !ok || key.Address != testSrc {
		t.Errorf("source-side entry = %+v, want the source address keyed as src", key)
	}
	if key, ok := seen[SideDst]; !ok || key.Address != testDst {
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
	if fold.Bytes != 0 || fold.Packets != 0 || fold.Flows != 0 {
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

// TestAggregator_InterfacesSplitOnlyTheConversationTables pins which tables
// the interface pair keys. Three of them already key one conversation, so the
// path it took is a property of that conversation and a pair reached over two
// paths reads as two entries. The other seven fold many conversations into one
// row, so keying the pair there multiplies the row by every path its members
// crossed -- and on the per-device table, which takes no Top-K cut, that moves
// the series bound from what the fleet was bought to what its ports are.
func TestAggregator_InterfacesSplitOnlyTheConversationTables(t *testing.T) {
	t.Parallel()

	base := testRecord()
	base.TOSReported = true
	base.TCPFlagsReported = true
	base.SrcCountry = "JP"
	base.DstCountry = "US"
	base.SrcFlagged = true
	base.DstFlagged = true
	base.SrcVLAN = 800
	base.DstVLAN = 801
	base.InputIf = 3
	base.OutputIf = 4

	byOutput := base
	byOutput.OutputIf = 5

	byInput := base
	byInput.InputIf = 6

	a := New(testConfig(), allModules())
	a.Ingest([]flow.Record{base, byOutput, byInput})

	hosts, _ := a.Hosts()
	services, _ := a.Services()
	threats, _ := a.Threats()
	exporters, _ := a.Exporters()
	destinations, _ := a.Destinations()
	tcpFlags, _ := a.TCPFlags()
	dscp, _ := a.DSCP()
	asns, _ := a.ASNs()
	apps, _ := a.Applications()
	countries, _ := a.Countries()
	vlans, _ := a.VLANs()

	// Both sides are flagged, so the threat table keys two entries per record.
	const threatsPerRecord = 2
	for _, tt := range []struct {
		name string
		got  int
		want int
	}{
		{"hosts", len(hosts), 3},
		{"services", len(services), 3},
		{"threats", len(threats), 3 * threatsPerRecord},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %d entries, want %d: each interface pair keys its own",
				tt.name, tt.got, tt.want)
		}
	}

	for _, tt := range []struct {
		name string
		got  int
	}{
		{"exporters", len(exporters)},
		{"destinations", len(destinations)},
		{"tcp flags", len(tcpFlags)},
		{"dscp", len(dscp)},
		{"asns", len(asns)},
		{"applications", len(apps)},
		{"countries", len(countries)},
		{"vlans", len(vlans)},
	} {
		if tt.got != 1 {
			t.Errorf("%s = %d entries, want 1: the interface pair must not key it", tt.name, tt.got)
		}
	}
}

// TestAggregator_IngestSaturatesAnUnrepresentableProduct pins the correction
// to a clamp. A wrapped product would hand the counter a reading below the one
// before it, which Prometheus reads as a reset rather than as a wrong number.
func TestAggregator_IngestSaturatesAnUnrepresentableProduct(t *testing.T) {
	t.Parallel()

	r := testRecord()
	r.Bytes = 1 << 63
	r.Packets = 1 << 63
	r.SamplingRate = 2

	a := New(testConfig(), allModules())
	a.Ingest([]flow.Record{r})

	exporters, _ := a.Exporters()
	if len(exporters) != 1 {
		t.Fatalf("Exporters() = %d entries, want 1", len(exporters))
	}
	if exporters[0].Bytes != math.MaxUint64 {
		t.Errorf("Exporters() bytes = %d, want %d", exporters[0].Bytes, uint64(math.MaxUint64))
	}
	if exporters[0].Packets != math.MaxUint64 {
		t.Errorf("Exporters() packets = %d, want %d", exporters[0].Packets, uint64(math.MaxUint64))
	}
}

// TestAggregator_PartsTheTwoObservationPointsOfOnePath pins the dimension
// every table gained. A device watching one transit path at its entry and its
// exit exports each flow twice with the same addresses, ports and interfaces,
// so without the point the two readings share a key and every table reports
// one flow of twice the traffic. Keying them apart does not correct the sum:
// summing across the label gives today's doubled figure back, and reading one
// direction is what gives the measured one.
func TestAggregator_PartsTheTwoObservationPointsOfOnePath(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), allModules())

	base := flow.Record{
		Exporter:         testExporter,
		Version:          flow.VersionNetFlowV9,
		SrcAddr:          testSrc,
		DstAddr:          testDst,
		Protocol:         6,
		DstPort:          443,
		TOSReported:      true,
		TCPFlags:         2,
		TCPFlagsReported: true,
		SrcAS:            64500,
		SrcVLAN:          800,
		SrcCountry:       "JP",
		AppName:          "https",
		SrcFlagged:       true,
		InputIf:          3,
		OutputIf:         4,
		Bytes:            1000,
		Packets:          10,
		Flows:            1,
	}
	ingress, egress := base, base
	ingress.Direction = flow.DirectionIngress
	egress.Direction = flow.DirectionEgress
	a.Ingest([]flow.Record{ingress, egress})

	for name, entries := range map[string]int{
		"exporters": lengthOf(a.Exporters()), "hosts": lengthOf(a.Hosts()),
		"services": lengthOf(a.Services()), "destinations": lengthOf(a.Destinations()),
		"tcp_flags": lengthOf(a.TCPFlags()), "dscp": lengthOf(a.DSCP()),
		"asns": lengthOf(a.ASNs()), "applications": lengthOf(a.Applications()),
		"countries": lengthOf(a.Countries()), "threats": lengthOf(a.Threats()),
		"vlans": lengthOf(a.VLANs()),
	} {
		if entries != 2 {
			t.Errorf("%s = %d entries, want one per observation point", name, entries)
		}
	}

	hosts, _ := a.Hosts()
	for _, e := range hosts {
		if e.Totals.Bytes != 1000 {
			t.Errorf("host entry at %s = %d bytes, want the one reading it carried",
				e.Key.Direction, e.Totals.Bytes)
		}
	}
}

// TestAggregator_KeysTheServiceSideOfTheConversation pins the port the two
// service families key on. A device exporting the return leg of a named
// service reports that service as the source port, so keying the destination
// unconditionally gave every reply its own entry under a client's ephemeral
// number -- a table of tens of thousands of rows naming nothing, with the
// service's own traffic split across them.
func TestAggregator_KeysTheServiceSideOfTheConversation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		src, dst uint16
		wantPort uint16
		wantSide Side
	}{
		{name: "the destination names it", src: 51234, dst: 443, wantPort: 443, wantSide: SideDst},
		{name: "the source names it", src: 443, dst: 51234, wantPort: 443, wantSide: SideSrc},
		{
			// Where both ends name a service the destination wins, being the
			// side a device exports as the service.
			name: "both name one", src: 53, dst: 123, wantPort: 123, wantSide: SideDst,
		},
		{
			// A client's own port names no service, so nothing is fabricated
			// and the destination keys it as it always has.
			name: "neither names one", src: 51234, dst: 60001, wantPort: 60001, wantSide: SideDst,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := New(testConfig(), Modules{Services: true, Destinations: true})
			r := testRecord()
			r.SrcPort, r.DstPort = tc.src, tc.dst
			a.Ingest([]flow.Record{r})

			services, _ := a.Services()
			if len(services) != 1 {
				t.Fatalf("Services() = %d entries, want 1", len(services))
			}
			if services[0].Key.Port != tc.wantPort || services[0].Key.Side != tc.wantSide {
				t.Errorf("service keyed on port %d side %s, want %d and %s",
					services[0].Key.Port, services[0].Key.Side, tc.wantPort, tc.wantSide)
			}

			destinations, _ := a.Destinations()
			if len(destinations) != 1 {
				t.Fatalf("Destinations() = %d entries, want 1", len(destinations))
			}
			if destinations[0].Key.Port != tc.wantPort || destinations[0].Key.Side != tc.wantSide {
				t.Errorf("destination keyed on port %d side %s, want %d and %s",
					destinations[0].Key.Port, destinations[0].Key.Side, tc.wantPort, tc.wantSide)
			}
		})
	}
}

// TestAggregator_FoldsTheReplyLegOntoTheServiceItAnswered pins what the rule
// is for. The two legs of one exchange carry the same service, so they belong
// in one entry rather than one per client port.
func TestAggregator_FoldsTheReplyLegOntoTheServiceItAnswered(t *testing.T) {
	t.Parallel()

	a := New(testConfig(), Modules{Destinations: true})

	records := make([]flow.Record, 0, 20)
	for client := range uint16(10) {
		request := testRecord()
		request.SrcPort, request.DstPort = 51000+client, 443
		reply := testRecord()
		reply.SrcPort, reply.DstPort = 443, 51000+client
		records = append(records, request, reply)
	}
	a.Ingest(records)

	entries, _ := a.Destinations()
	if len(entries) != 2 {
		t.Errorf("Destinations() = %d entries, want one per side of the one service", len(entries))
	}
	for _, e := range entries {
		if e.Key.Port != 443 {
			t.Errorf("entry keyed on port %d, want the service both legs name", e.Key.Port)
		}
	}
}

// TestAggregator_ServiceLookupReadsTheOperatorsOwnPorts pins the hand-off the
// server makes. The built-in table deliberately names no internal service, so
// without the mapping file the rule would reach only the fifty-odd ports it
// does carry.
func TestAggregator_ServiceLookupReadsTheOperatorsOwnPorts(t *testing.T) {
	t.Parallel()

	const internal = 9100

	a := New(testConfig(), Modules{Destinations: true},
		WithServiceLookup(func(protocol uint8, port uint16) bool {
			return protocol == 6 && port == internal
		}))

	r := testRecord()
	r.SrcPort, r.DstPort = internal, 51234
	a.Ingest([]flow.Record{r})

	entries, _ := a.Destinations()
	if len(entries) != 1 {
		t.Fatalf("Destinations() = %d entries, want 1", len(entries))
	}
	if entries[0].Key.Port != internal || entries[0].Key.Side != SideSrc {
		t.Errorf("keyed on port %d side %s, want the declared %d as the source side",
			entries[0].Key.Port, entries[0].Key.Side, internal)
	}
}
