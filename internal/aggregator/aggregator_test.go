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
	return Modules{Exporters: true, Hosts: true, Services: true, ASNs: true, Applications: true}
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
