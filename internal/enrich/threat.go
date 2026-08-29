// Package enrich fills flow record dimensions the exporting device did not
// carry, from sources local to this exporter.
// This file flags addresses against a reputation API.
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// The AbuseIPDB check endpoint and the header its key travels in.
const (
	abuseIPDBEndpoint  = "https://api.abuseipdb.com/api/v2/check"
	abuseIPDBKeyHeader = "Key"
)

// abuseIPDBResponse is the shape the check endpoint answers with. Only the
// confidence score is read: it is what the threshold compares against.
//
// The tags spell the service's own field names, which are camel case. They
// are an external contract rather than this project's own JSON, so the
// naming rule does not apply to them.
//
//nolint:tagliatelle // The service names these fields, not this project.
type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

// ThreatConfig holds what the reputation lookup needs.
type ThreatConfig struct {
	// APIKey authenticates to the reputation service. Enrichment is off
	// without one.
	APIKey string
	// Threshold is the confidence at or above which an address is flagged.
	Threshold int
	// CacheTTL is how long a verdict is reused before it is asked again.
	CacheTTL time.Duration
	// CacheSize bounds the verdicts held.
	CacheSize int
	// Timeout bounds one lookup.
	Timeout time.Duration
}

// verdict is one address's cached answer.
type verdict struct {
	flagged bool
	expires time.Time
}

// Threat flags addresses a reputation service reports as abusive.
//
// Only public addresses are ever sent. An address inside the monitored
// network is the operator's own, the service holds nothing on it, and
// shipping it to a third party would leak the network's internal structure
// for no answer in return.
//
// The lookup is asynchronous: the record being enriched is flagged from the
// cache alone, and a miss queues the address for a later scrape to benefit
// from. A synchronous call would put a third party's latency on the decode
// path, where a slow answer costs datagrams.
type Threat struct {
	counters
	cfg    ThreatConfig
	client *http.Client

	mu      sync.Mutex
	cache   map[netip.Addr]verdict
	pending map[netip.Addr]bool
	queue   chan netip.Addr

	// now is pinned by tests.
	now func() time.Time
	// lookup is the seam a test replaces, the production one calling the API.
	lookup func(context.Context, netip.Addr) (bool, error)

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	errors atomic.Uint64
}

// NewThreat creates the reputation enricher and starts its lookup worker.
func NewThreat(cfg ThreatConfig) (*Threat, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("a reputation API key is required to flag addresses")
	}

	t := &Threat{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.Timeout},
		cache:   make(map[netip.Addr]verdict),
		pending: make(map[netip.Addr]bool),
		queue:   make(chan netip.Addr, cfg.CacheSize),
		now:     time.Now,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	t.lookup = t.lookupAPI

	go t.run()
	return t, nil
}

// Name implements Enricher.
func (t *Threat) Name() string {
	return "threat"
}

// Snapshot implements Enricher.
func (t *Threat) Snapshot() Snapshot {
	return t.snapshot(t.Name())
}

// Errors reports the lookups that failed since process start.
func (t *Threat) Errors() uint64 {
	return t.errors.Load()
}

// Close stops the lookup worker.
func (t *Threat) Close() error {
	t.stopOnce.Do(func() { close(t.stop) })
	<-t.done
	return nil
}

// Enrich flags each side from the cache, queueing what it has no verdict for.
func (t *Threat) Enrich(r *flow.Record) {
	srcKnown := t.check(r.SrcAddr, &r.SrcFlagged)
	dstKnown := t.check(r.DstAddr, &r.DstFlagged)

	switch {
	case srcKnown || dstKnown:
		t.filled.Add(1)
	default:
		t.unknown.Add(1)
	}
}

// check flags one side from the cache and reports whether a verdict existed.
func (t *Threat) check(addr netip.Addr, flagged *bool) bool {
	if !isPublic(addr) {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if v, ok := t.cache[addr]; ok && t.now().Before(v.expires) {
		*flagged = v.flagged
		return true
	}

	t.enqueueLocked(addr)
	return false
}

// enqueueLocked queues one address for the worker, at most once at a time.
// A full queue drops the request: the address returns on the next record.
func (t *Threat) enqueueLocked(addr netip.Addr) {
	if t.pending[addr] {
		return
	}

	select {
	case t.queue <- addr:
		t.pending[addr] = true
	default:
	}
}

// run resolves queued addresses until Close.
func (t *Threat) run() {
	defer close(t.done)

	for {
		select {
		case <-t.stop:
			return
		case addr := <-t.queue:
			t.resolve(addr)
		}
	}
}

// resolve asks the service about one address and caches the answer. A failed
// lookup is cached as unflagged for the TTL, so a service that is down costs
// one request per address per TTL rather than one per record.
func (t *Threat) resolve(addr netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), t.cfg.Timeout)
	defer cancel()

	flagged, err := t.lookup(ctx, addr)
	if err != nil {
		t.errors.Add(1)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.pending, addr)
	t.evictLocked()
	t.cache[addr] = verdict{flagged: flagged, expires: t.now().Add(t.cfg.CacheTTL)}
}

// evictLocked drops expired entries once the cache is full, and gives up the
// oldest remaining one when nothing has expired.
func (t *Threat) evictLocked() {
	if len(t.cache) < t.cfg.CacheSize {
		return
	}

	now := t.now()
	for addr, v := range t.cache {
		if !now.Before(v.expires) {
			delete(t.cache, addr)
		}
	}
	if len(t.cache) < t.cfg.CacheSize {
		return
	}

	oldest, found := netip.Addr{}, false
	for addr, v := range t.cache {
		if !found || v.expires.Before(t.cache[oldest].expires) {
			oldest, found = addr, true
		}
	}
	if found {
		delete(t.cache, oldest)
	}
}

// lookupAPI asks AbuseIPDB about one address.
func (t *Threat) lookupAPI(ctx context.Context, addr netip.Addr) (bool, error) {
	return t.lookupAt(ctx, abuseIPDBEndpoint, addr)
}

// lookupAt asks the service at endpoint about one address. The endpoint is a
// parameter so a test can point it at a stub rather than the real service.
func (t *Threat) lookupAt(ctx context.Context, endpoint string, addr netip.Addr) (bool, error) {
	query := url.Values{}
	query.Set("ipAddress", addr.String())
	query.Set("maxAgeInDays", "90")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"?"+query.Encode(), http.NoBody)
	if err != nil {
		return false, fmt.Errorf("building the reputation request: %w", err)
	}
	req.Header.Set(abuseIPDBKeyHeader, t.cfg.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("asking the reputation service: %w", err)
	}
	defer closeBody(resp)

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("the reputation service answered %s", resp.Status)
	}

	var answer abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return false, fmt.Errorf("decoding the reputation answer: %w", err)
	}

	return answer.Data.AbuseConfidenceScore >= t.cfg.Threshold, nil
}

// closeBody releases one response. A close failure changes nothing for the
// caller, the answer having been read already.
func closeBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		slog.Debug("Failed to close the reputation response", "error", err)
	}
}

// isPublic reports whether an address may be sent to a third party. Anything
// the monitored network assigns itself is out: the service holds nothing on
// it, and sending it would leak the network's structure for no answer.
func isPublic(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified() &&
		!addr.IsInterfaceLocalMulticast()
}
