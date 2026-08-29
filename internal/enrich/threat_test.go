package enrich

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// newTestThreat builds an enricher whose lookups are answered by lookup,
// without starting the worker: the tests drive resolve directly so they stay
// deterministic.
func newTestThreat(t *testing.T, lookup func(netip.Addr) bool) *Threat {
	t.Helper()

	th := &Threat{
		cfg: ThreatConfig{
			Threshold: 50,
			CacheTTL:  time.Hour,
			CacheSize: 8,
			Timeout:   time.Second,
		},
		cache:   make(map[netip.Addr]verdict),
		pending: make(map[netip.Addr]bool),
		queue:   make(chan netip.Addr, 8),
		now:     time.Now,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	th.lookup = func(_ context.Context, addr netip.Addr) (bool, error) {
		return lookup(addr), nil
	}
	return th
}

// TestThreat_PrivateAddressesAreNeverSent is the privacy guard, and the most
// important property in this file: an address inside the monitored network
// must not reach a third party.
func TestThreat_PrivateAddressesAreNeverSent(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var sent []netip.Addr

	th := newTestThreat(t, func(addr netip.Addr) bool {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, addr)
		return true
	})

	internal := []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC 1918
		"127.0.0.1",   // loopback
		"169.254.1.1", // link-local
		"224.0.0.1",   // multicast
		"0.0.0.0",     // unspecified
		"fd00::1",     // unique local
		"fe80::1",     // link-local v6
		"::1",         // loopback v6
	}
	for _, addr := range internal {
		r := flow.Record{SrcAddr: netip.MustParseAddr(addr), DstAddr: netip.MustParseAddr(addr)}
		th.Enrich(&r)

		if r.SrcFlagged || r.DstFlagged {
			t.Errorf("%s was flagged, want an internal address left alone", addr)
		}
	}

	// Nothing was queued, so nothing can ever be sent.
	if len(th.queue) != 0 {
		t.Errorf("%d addresses were queued, want none", len(th.queue))
	}

	// Drain whatever the worker would have resolved, to be certain.
	close(th.stop)
	close(th.done)

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 0 {
		t.Errorf("these internal addresses reached the lookup: %v", sent)
	}
}

func TestThreat_FlagsFromTheCache(t *testing.T) {
	t.Parallel()

	bad := netip.MustParseAddr("198.51.100.7")
	good := netip.MustParseAddr("203.0.113.9")

	th := newTestThreat(t, func(addr netip.Addr) bool { return addr == bad })

	// The first record has no verdict yet and queues both sides.
	r := flow.Record{SrcAddr: bad, DstAddr: good}
	th.Enrich(&r)
	if r.SrcFlagged || r.DstFlagged {
		t.Errorf("record = %+v, want nothing flagged before a verdict exists", r)
	}
	if got := th.Snapshot(); got.Unknown != 1 {
		t.Errorf("Snapshot() = %+v, want one unknown", got)
	}

	// Resolve what the enrichment queued.
	th.resolve(bad)
	th.resolve(good)

	r = flow.Record{SrcAddr: bad, DstAddr: good}
	th.Enrich(&r)
	if !r.SrcFlagged {
		t.Error("SrcFlagged = false, want the flagged address marked")
	}
	if r.DstFlagged {
		t.Error("DstFlagged = true, want a clean address unmarked")
	}
	if got := th.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}
}

// TestThreat_VerdictsExpire pins that a verdict is asked again once its TTL
// passes, a reputation being a moving fact.
func TestThreat_VerdictsExpire(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("198.51.100.7")
	th := newTestThreat(t, func(netip.Addr) bool { return true })

	now := time.Unix(1_756_800_000, 0)
	th.now = func() time.Time { return now }

	th.resolve(addr)

	r := flow.Record{SrcAddr: addr}
	th.Enrich(&r)
	if !r.SrcFlagged {
		t.Fatal("SrcFlagged = false within the TTL, want the verdict applied")
	}

	now = now.Add(2 * time.Hour)
	r = flow.Record{SrcAddr: addr}
	th.Enrich(&r)
	if r.SrcFlagged {
		t.Error("SrcFlagged = true past the TTL, want the stale verdict dropped")
	}
}

// TestThreat_CacheIsBounded pins that the verdict cache cannot grow without
// end, the addresses being wire data.
func TestThreat_CacheIsBounded(t *testing.T) {
	t.Parallel()

	th := newTestThreat(t, func(netip.Addr) bool { return false })

	for i := range 64 {
		th.resolve(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}

	th.mu.Lock()
	defer th.mu.Unlock()
	if len(th.cache) > th.cfg.CacheSize {
		t.Errorf("cache holds %d verdicts, want at most %d", len(th.cache), th.cfg.CacheSize)
	}
}

// TestThreat_FailedLookupsAreCountedAndCached pins that a service that is
// down costs one request per address per TTL rather than one per record.
func TestThreat_FailedLookupsAreCountedAndCached(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("198.51.100.7")
	th := newTestThreat(t, func(netip.Addr) bool { return false })
	th.lookup = func(context.Context, netip.Addr) (bool, error) {
		return false, errors.New("the service is unreachable")
	}

	th.resolve(addr)

	if th.Errors() != 1 {
		t.Errorf("Errors() = %d, want 1", th.Errors())
	}

	r := flow.Record{SrcAddr: addr}
	th.Enrich(&r)
	if r.SrcFlagged {
		t.Error("SrcFlagged = true after a failed lookup, want an unproven address unflagged")
	}
	if got := th.Snapshot(); got.Filled != 1 {
		t.Errorf("Snapshot() = %+v, want the cached miss to count as a verdict", got)
	}
}

// TestThreat_LookupAPIReadsTheScore covers the production lookup against a
// stub of the service, including the threshold comparison and the key header.
func TestThreat_LookupAPIReadsTheScore(t *testing.T) {
	t.Parallel()

	var gotKey, gotIP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get(abuseIPDBKeyHeader)
		gotIP = r.URL.Query().Get("ipAddress")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":75}}`))
	}))
	defer server.Close()

	th := newTestThreat(t, nil)
	th.cfg.APIKey = "secret-key"
	th.client = server.Client()

	// Point the production lookup at the stub by rebuilding its request URL.
	addr := netip.MustParseAddr("198.51.100.7")
	flagged, err := th.lookupAt(context.Background(), server.URL, addr)
	if err != nil {
		t.Fatalf("lookupAt() error = %v, want nil", err)
	}
	if !flagged {
		t.Error("flagged = false for a score of 75 against a threshold of 50, want true")
	}
	if gotKey != "secret-key" {
		t.Errorf("the service saw key %q, want it sent in the header", gotKey)
	}
	if gotIP != addr.String() {
		t.Errorf("the service saw address %q, want %q", gotIP, addr)
	}
}

// TestThreat_LookupAPIRejectsAnErrorStatus pins that a non-200 is an error
// rather than a clean verdict.
func TestThreat_LookupAPIRejectsAnErrorStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	th := newTestThreat(t, nil)
	th.client = server.Client()

	if _, err := th.lookupAt(context.Background(), server.URL,
		netip.MustParseAddr("198.51.100.7")); err == nil {
		t.Error("lookupAt() error = nil for a 429, want it reported")
	}
}

// TestThreat_RequiresAnAPIKey pins that the enricher cannot start without one.
func TestThreat_RequiresAnAPIKey(t *testing.T) {
	t.Parallel()

	if _, err := NewThreat(ThreatConfig{}); err == nil {
		t.Error("NewThreat() error = nil without a key, want it refused")
	}
}

// TestThreat_WorkerStopsOnClose covers the lifecycle of the real constructor.
func TestThreat_WorkerStopsOnClose(t *testing.T) {
	t.Parallel()

	th, err := NewThreat(ThreatConfig{
		APIKey:    "k",
		Threshold: 50,
		CacheTTL:  time.Hour,
		CacheSize: 4,
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("NewThreat() error = %v, want nil", err)
	}

	done := make(chan error, 1)
	go func() { done <- th.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close() error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return, the worker is still running")
	}

	// Close is idempotent, which a deferred Close alongside an explicit one
	// depends on.
	if err := th.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
}
