package server

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/collector"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// spoofedAddr is a distinct address per index, which is what a sender writes
// into a UDP header at no cost.
func spoofedAddr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// TestSweepDomains_ReclaimsTheExporterBudget pins what the running process
// recovers from without being restarted. A burst of spoofed source addresses
// fills the exporter budget, and every device first seen afterwards is refused
// outright: no counters, no freshness series, nothing a silence alert can
// read. Only the loop returns those slots, and only on its own schedule, so a
// flood costs a template TTL rather than an operator.
//
// Time in the bubble is virtual: the loop floors its interval at a second,
// which a real tick would spend out of every run of the suite.
func TestSweepDomains_ReclaimsTheExporterBudget(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const ttl = time.Millisecond
		dec := decoder.New(config.Parser{
			MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          ttl,
		})

		// Two bytes no version claims: accounted against its source address
		// and nothing else, which is the path a spoofed burst reaches first.
		burst := []byte{0xff, 0xff}
		// The budget is a decoder constant, so it is filled until it refuses
		// rather than counted to. The bound only stops a runaway loop.
		const maxFill = 1 << 20
		for i := range maxFill {
			_, _ = dec.Decode(spoofedAddr(i), burst, nil)
			if dec.ExportersRefused() > 0 {
				break
			}
		}
		refused := dec.ExportersRefused()
		if refused == 0 {
			t.Fatalf("%d spoofed addresses did not reach the exporter budget", maxFill)
		}

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			sweepDomains(ctx, dec, nil, ttl)
		}()

		// Past one tick of the floored interval, with the burst idle since
		// long before the cutoff it is swept on.
		time.Sleep(2 * time.Second)
		synctest.Wait()
		cancel()
		<-done

		fresh := netip.MustParseAddr("203.0.113.9")
		_, _ = dec.Decode(fresh, burst, nil)

		var admitted bool
		for _, snap := range dec.Stats().Snapshot() {
			if snap.Exporter == fresh {
				admitted = true
			}
		}
		if !admitted {
			t.Error("a device seen after the sweep holds no counters, want the reclaimed slot to admit it")
		}
		if got := dec.ExportersRefused(); got != refused {
			t.Errorf("ExportersRefused() = %d, want it held at %d: the slots were reclaimed", got, refused)
		}
	})
}

// TestSweepDomains_ReleasesTheSeriesWithTheSlot pins the other half of the
// reclaim above. A histogram child outlives the device that made it, so the
// sweep drops it with the slot.
func TestSweepDomains_ReleasesTheSeriesWithTheSlot(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const ttl = time.Millisecond
		dec := decoder.New(config.Parser{
			MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          ttl,
		})

		burst := []byte{0xff, 0xff}
		const maxFill = 1 << 20
		for i := range maxFill {
			_, _ = dec.Decode(spoofedAddr(i), burst, nil)
			if dec.ExportersRefused() > 0 {
				break
			}
		}
		if dec.ExportersRefused() == 0 {
			t.Fatalf("%d spoofed addresses did not reach the exporter budget", maxFill)
		}

		reg := prometheus.NewRegistry()
		dist := collector.NewDistributions()
		dist.Register(reg)
		dist.Observe([]flow.Record{{
			Exporter:      spoofedAddr(0),
			Version:       flow.VersionNetFlowV9,
			Bytes:         1024,
			Packets:       1,
			BytesReported: true,
			Flows:         1,
		}})
		if got := seriesCount(t, reg); got != 1 {
			t.Fatalf("series before the sweep = %d, want the observation to have made one", got)
		}

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			sweepDomains(ctx, dec, dist, ttl)
		}()

		time.Sleep(2 * time.Second)
		synctest.Wait()
		cancel()
		<-done

		if got := seriesCount(t, reg); got != 0 {
			t.Errorf("series after the sweep = %d, want the swept device to hold none", got)
		}
	})
}
