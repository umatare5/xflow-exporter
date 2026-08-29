package server

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
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
			sweepDomains(ctx, dec, ttl)
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
