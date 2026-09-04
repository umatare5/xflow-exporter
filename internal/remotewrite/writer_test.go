package remotewrite

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/snappy"
	writev2 "github.com/prometheus/client_golang/exp/api/remote/genproto/v2"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// writePath is where the stub serves, and the path a configured URL carries.
// The client takes the base and the path separately, so a URL passed whole
// would post to the client's own default and answer 404 here.
const writePath = "/api/v1/write"

// capture records what one write carried.
type capture struct {
	mu      sync.Mutex
	request *writev2.Request
	headers http.Header
	status  int
}

// endpoint stands in for a Remote Write 2.0 receiver, decoding what it is
// sent so the test asserts on the real wire form rather than on intent.
func endpoint(t *testing.T, c *capture) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/write", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the write body: %v", err)
			return
		}
		decoded, err := snappy.Decode(nil, body)
		if err != nil {
			t.Errorf("decompressing the write body: %v", err)
			return
		}

		var req writev2.Request
		if err := proto.Unmarshal(decoded, &req); err != nil {
			t.Errorf("decoding the write request: %v", err)
			return
		}

		c.mu.Lock()
		c.request = &req
		c.headers = r.Header.Clone()
		status := c.status
		c.mu.Unlock()

		if status != 0 {
			w.WriteHeader(status)
			return
		}

		// Remote Write 2.0 requires the receiver to report what it accepted.
		// A 2xx without these reads as a 1.0 endpoint mishandling the
		// content type, which the client rejects, so the stub answers as the
		// specification says a 2.0 receiver must.
		written := 0
		for _, series := range req.Timeseries {
			written += len(series.Samples)
		}
		w.Header().Set("X-Prometheus-Remote-Write-Samples-Written", strconv.Itoa(written))
		w.Header().Set("X-Prometheus-Remote-Write-Histograms-Written", "0")
		w.Header().Set("X-Prometheus-Remote-Write-Exemplars-Written", "0")
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(mux)
}

// testRegistry holds one counter and one gauge with distinct label sets.
func testRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()

	reg := prometheus.NewRegistry()

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "xflow_probe_total", Help: "probe"},
		[]string{"exporter_address"},
	)
	counter.WithLabelValues("192.0.2.1").Add(7)
	reg.MustRegister(counter)

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "xflow_probe_gauge", Help: "probe"})
	gauge.Set(3)
	reg.MustRegister(gauge)

	return reg
}

// newTestWriter builds a writer aimed at the stub with a pinned clock.
func newTestWriter(t *testing.T, url string, reg prometheus.Gatherer) *Writer {
	t.Helper()

	w, err := New(config.RemoteWrite{
		URL:      url,
		Interval: time.Minute,
		Timeout:  5 * time.Second,
	}, reg)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	w.now = func() time.Time { return time.Unix(1_756_900_000, 0) }
	return w
}

func TestWriter_ShipsTheRegistry(t *testing.T) {
	t.Parallel()

	c := &capture{}
	server := endpoint(t, c)
	defer server.Close()

	w := newTestWriter(t, server.URL+writePath, testRegistry(t))
	if err := w.send(context.Background()); err != nil {
		t.Fatalf("send() error = %v, want nil", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.request == nil {
		t.Fatal("the endpoint received nothing")
	}
	if got := len(c.request.Timeseries); got != 2 {
		t.Fatalf("the endpoint received %d series, want 2", got)
	}

	// The symbol table must start with the empty string, which the
	// specification requires at index zero.
	if len(c.request.Symbols) == 0 || c.request.Symbols[0] != "" {
		t.Errorf("symbols = %q, want the empty string first", c.request.Symbols)
	}

	// Resolve one series back through the symbol table and check it round
	// trips: this is what proves the encoding, not the intent.
	names := map[string]float64{}
	for _, series := range c.request.Timeseries {
		labels := resolve(t, c.request.Symbols, series.LabelsRefs)
		if len(series.Samples) != 1 {
			t.Fatalf("series %v carries %d samples, want 1", labels, len(series.Samples))
		}
		names[labels["__name__"]] = series.Samples[0].Value
	}

	if got := names["xflow_probe_total"]; got != 7 {
		t.Errorf("xflow_probe_total = %v, want 7", got)
	}
	if got := names["xflow_probe_gauge"]; got != 3 {
		t.Errorf("xflow_probe_gauge = %v, want 3", got)
	}

	snap := w.Stats().Snapshot()
	if snap.Sends != 1 || snap.Failures != 0 || snap.Samples != 2 {
		t.Errorf("Snapshot() = %+v, want one send of two series", snap)
	}
	if snap.LastSuccessUnixNano == 0 {
		t.Error("LastSuccessUnixNano = 0 after a success, want it stamped")
	}
}

// resolve turns one series' references back into labels.
func resolve(t *testing.T, symbols []string, refs []uint32) map[string]string {
	t.Helper()

	if len(refs)%refsPerPair != 0 {
		t.Fatalf("label refs = %v, want name and value pairs", refs)
	}

	labels := make(map[string]string, len(refs)/refsPerPair)
	var previous string
	for i := 0; i < len(refs); i += refsPerPair {
		name := symbols[refs[i]]
		if previous != "" && name < previous {
			t.Errorf("labels are out of order at %q after %q, want them sorted", name, previous)
		}
		previous = name
		labels[name] = symbols[refs[i+1]]
	}
	return labels
}

// TestWriter_SendsCredentialsAndHeaders covers the transport.
func TestWriter_SendsCredentialsAndHeaders(t *testing.T) {
	t.Parallel()

	c := &capture{}
	server := endpoint(t, c)
	defer server.Close()

	w, err := New(config.RemoteWrite{
		URL:      server.URL + writePath,
		Interval: time.Minute,
		Timeout:  5 * time.Second,
		Username: "user",
		Password: "secret",
		Headers:  map[string]string{"X-Scope-OrgID": "tenant-a"},
	}, testRegistry(t))
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	if err := w.send(context.Background()); err != nil {
		t.Fatalf("send() error = %v, want nil", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	user, pass, ok := parseBasicAuth(c.headers.Get("Authorization"))
	if !ok || user != "user" || pass != "secret" {
		t.Errorf("Authorization = %q, want the configured basic auth", c.headers.Get("Authorization"))
	}
	if got := c.headers.Get("X-Scope-OrgID"); got != "tenant-a" {
		t.Errorf("X-Scope-OrgID = %q, want tenant-a", got)
	}
}

// parseBasicAuth reads the header the transport set.
func parseBasicAuth(header string) (username, password string, ok bool) {
	req := &http.Request{Header: http.Header{"Authorization": []string{header}}}
	return req.BasicAuth()
}

// TestWriter_CountsFailures pins that a rejected write is visible rather
// than silent.
func TestWriter_CountsFailures(t *testing.T) {
	t.Parallel()

	c := &capture{status: http.StatusBadRequest}
	server := endpoint(t, c)
	defer server.Close()

	w := newTestWriter(t, server.URL+writePath, testRegistry(t))
	if err := w.send(context.Background()); err == nil {
		t.Fatal("send() error = nil for a rejected write, want it reported")
	}

	snap := w.Stats().Snapshot()
	if snap.Failures == 0 {
		t.Error("Failures = 0 after a rejection, want it counted")
	}
	if snap.LastSuccessUnixNano != 0 {
		t.Error("LastSuccessUnixNano is set after a failure, want it absent")
	}
}

// TestWriter_HistogramsAreSkipped pins the documented gap: a native histogram
// is its own Remote Write message, and shipping it as a single sample would
// be a fabricated value.
func TestWriter_HistogramsAreSkipped(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "xflow_probe_bytes", Help: "probe",
		NativeHistogramBucketFactor: 1.1,
	})
	histogram.Observe(1500)
	reg.MustRegister(histogram)

	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "xflow_probe_total", Help: "probe"})
	counter.Add(1)
	reg.MustRegister(counter)

	c := &capture{}
	server := endpoint(t, c)
	defer server.Close()

	w := newTestWriter(t, server.URL+writePath, reg)
	if err := w.send(context.Background()); err != nil {
		t.Fatalf("send() error = %v, want nil", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if got := len(c.request.Timeseries); got != 1 {
		t.Errorf("the endpoint received %d series, want only the counter", got)
	}
}

// TestWriter_EmptyRegistrySendsNothing pins that an exporter with no series
// does not write an empty request every interval.
func TestWriter_EmptyRegistrySendsNothing(t *testing.T) {
	t.Parallel()

	c := &capture{}
	server := endpoint(t, c)
	defer server.Close()

	w := newTestWriter(t, server.URL+writePath, prometheus.NewRegistry())
	if err := w.send(context.Background()); err != nil {
		t.Fatalf("send() error = %v, want nil", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.request != nil {
		t.Error("the endpoint received a request for an empty registry, want none")
	}
	if got := w.Stats().Snapshot().Sends; got != 0 {
		t.Errorf("Sends = %d, want none", got)
	}
}

// TestWriter_SymbolTableIsReused pins that consecutive sends do not carry the
// leftovers of the previous one.
func TestWriter_SymbolTableIsReused(t *testing.T) {
	t.Parallel()

	c := &capture{}
	server := endpoint(t, c)
	defer server.Close()

	w := newTestWriter(t, server.URL+writePath, testRegistry(t))
	for range 3 {
		if err := w.send(context.Background()); err != nil {
			t.Fatalf("send() error = %v, want nil", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// The same registry each time, so the table must be the same size each
	// time rather than growing.
	if got := len(c.request.Symbols); got > 8 {
		t.Errorf("symbols = %d after three sends, want the table reset between them", got)
	}
	for _, symbol := range c.request.Symbols {
		if strings.Count(symbol, "xflow_probe_total") > 1 {
			t.Errorf("symbol %q repeats, want each interned once", symbol)
		}
	}
}

// TestWriter_RunStopsOnCancel covers the loop's lifecycle.
func TestWriter_RunStopsOnCancel(t *testing.T) {
	t.Parallel()

	c := &capture{}
	server := endpoint(t, c)
	defer server.Close()

	w := newTestWriter(t, server.URL+writePath, testRegistry(t))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Run(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

// TestNew_RejectsABrokenURL pins that a malformed endpoint fails at
// construction rather than on the first write.
func TestNew_RejectsABrokenURL(t *testing.T) {
	t.Parallel()

	if _, err := New(config.RemoteWrite{URL: "://not a url"}, prometheus.NewRegistry()); err == nil {
		t.Error("New() error = nil for a malformed URL, want it refused")
	}
}
