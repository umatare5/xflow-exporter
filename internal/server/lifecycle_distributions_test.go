package server

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/collector"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// seriesCount reports how many histogram series the registry holds.
func seriesCount(t *testing.T, reg *prometheus.Registry) int {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, mf := range families {
		if mf.GetName() == "xflow_flow_bytes" {
			return len(mf.GetMetric())
		}
	}
	return 0
}

// observeOne drives one datagram from addr through the decode loop and
// reports how many histogram series it left behind.
func observeOne(t *testing.T, dec *decoder.Decoder, addr netip.Addr) int {
	t.Helper()

	recv := receiver.New(config.Receiver{MaxPacketSize: 128, QueueSize: 1})
	chain, _, _, _, err := buildEnrichmentChain(config.Enrichment{})
	if err != nil {
		t.Fatalf("buildEnrichmentChain() error = %v, want nil", err)
	}
	reg := prometheus.NewRegistry()
	dist := collector.NewDistributions()
	dist.Register(reg)

	in := make(chan receiver.Packet, 1)
	in <- receiver.Packet{Src: netip.AddrPortFrom(addr, 2055), Data: netflowV5Datagram()}
	close(in)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		decodeLoop(recv, in, dec, chain, nil, dist)
	}()
	wg.Wait()

	return seriesCount(t, reg)
}

// TestDecodeLoop_ObservesOnlyWhatTheBudgetAdmits pins the gate on the
// histogram consumer, which the vector itself does not bound.
func TestDecodeLoop_ObservesOnlyWhatTheBudgetAdmits(t *testing.T) {
	t.Parallel()

	dec := decoder.New(config.Parser{
		MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
		TemplateTTL:          config.DefaultParserTemplateTTL,
	})

	if got := observeOne(t, dec, netip.MustParseAddr("192.0.2.1")); got != 1 {
		t.Fatalf("series for an admitted device = %d, want 1", got)
	}

	// A device takes its slot before the version is sniffed, so a datagram
	// too short to decode still fills the budget.
	var refused netip.Addr
	for i := range 1 << 20 {
		addr := spoofedAddr(i)
		_, _ = dec.Decode(sentFrom(addr), []byte{0, 0, 0, 0}, nil)
		if !dec.Admits(addr) {
			refused = addr
			break
		}
	}
	if !refused.IsValid() {
		t.Fatal("the exporter budget never refused a device, want it filled")
	}

	if got := observeOne(t, dec, refused); got != 0 {
		t.Errorf("series for a refused device = %d, want none", got)
	}
}
