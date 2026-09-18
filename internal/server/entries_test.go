package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/collector"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/server"
)

// stubLister answers as a collector with hosts enabled and services disabled.
// A non-nil release holds a listing inside Entries, after entered reports it
// has taken the in-flight slot.
type stubLister struct {
	entered chan struct{}
	release chan struct{}
	holding atomic.Bool
}

func (s *stubLister) Aggregations() []string {
	return []string{"exporters", "hosts", "services"}
}

func (s *stubLister) EntryScope() (topK int, minBytes uint64) {
	return 2, 100
}

func (s *stubLister) Entries(name string) (collector.AggregationEntries, bool) {
	// Only the first listing waits: a second one reaching this point means the
	// in-flight bound let it through, which has to fail as an assertion rather
	// than as a deadlock.
	if s.release != nil && s.holding.CompareAndSwap(false, true) {
		close(s.entered)
		<-s.release
	}
	if name == "services" {
		return collector.AggregationEntries{}, false
	}
	return collector.AggregationEntries{
		Entries:    3,
		Published:  2,
		Withheld:   1,
		LabelNames: []string{"exporter_address"},
		Rows:       []collector.EntryRow{{Rank: 1, Labels: []string{"192.0.2.1"}}},
	}, true
}

func entriesServer(t *testing.T, lister server.EntryLister) *http.Server {
	t.Helper()

	return server.New(probeRegistry(t), ":8080", config.DefaultTelemetryPath, nil, lister)
}

func get(t *testing.T, srv *http.Server, target string) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, http.NoBody))
	return w
}

// TestServer_EntriesNeedTheFlag pins what the path answers unregistered. The
// mux answers every unclaimed path with the landing page, so the absent flag
// reads as 200 and HTML rather than as 404.
func TestServer_EntriesNeedTheFlag(t *testing.T) {
	t.Parallel()

	w := get(t, entriesServer(t, nil), config.EntriesPath)

	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want the landing page without the flag", got)
	}
	if strings.Contains(w.Body.String(), "aggregations") {
		t.Errorf("body = %q, want no listing without the flag", w.Body.String())
	}
}

// TestServer_EntriesAcceptGETAlone pins the method check. The listing reads
// the whole table, so a crawler must not start one by POSTing.
func TestServer_EntriesAcceptGETAlone(t *testing.T) {
	t.Parallel()

	srv := entriesServer(t, &stubLister{})

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, config.EntriesPath, http.NoBody))

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST %s = %d, want %d", config.EntriesPath, w.Code, http.StatusMethodNotAllowed)
	}
	if got := w.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow = %q, want %q", got, http.MethodGet)
	}
}

// TestServer_EntriesRefuseWhatTheyCannotName pins the parameter contract. A
// misspelling is a client error naming the accepted values, and an empty or
// repeated value is one too rather than a silent read of the first.
func TestServer_EntriesRefuseWhatTheyCannotName(t *testing.T) {
	t.Parallel()

	srv := entriesServer(t, &stubLister{})

	for _, target := range []string{
		config.EntriesPath + "?aggregation=tcp_flag",
		config.EntriesPath + "?aggregation=",
		config.EntriesPath + "?aggregation=hosts&aggregation=exporters",
		// Query drops the pairs it cannot parse, so these would otherwise
		// arrive as an absent parameter and list every table.
		config.EntriesPath + "?aggregation=%zz",
		config.EntriesPath + "?aggregation=hosts;aggregation=exporters",
	} {
		w := get(t, srv, target)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want %d", target, w.Code, http.StatusBadRequest)
		}
		if !strings.Contains(w.Body.String(), "hosts") {
			t.Errorf("GET %s body = %q, want the accepted names", target, w.Body.String())
		}
	}
}

// TestServer_EntriesServeJSON pins the response. A disabled table carries no
// key, which is the absence its series have, and the scope says which cuts
// the ranks were taken under.
func TestServer_EntriesServeJSON(t *testing.T) {
	t.Parallel()

	srv := entriesServer(t, &stubLister{})

	w := get(t, srv, config.EntriesPath)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want %d", config.EntriesPath, w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var report struct {
		TopK         int                                     `json:"top_k"`
		MinBytes     uint64                                  `json:"min_bytes"`
		Aggregations map[string]collector.AggregationEntries `json:"aggregations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("Unmarshal() error = %v, body = %q", err, w.Body.String())
	}

	if report.TopK != 2 || report.MinBytes != 100 {
		t.Errorf("top_k/min_bytes = %d/%d, want 2/100", report.TopK, report.MinBytes)
	}
	if _, listed := report.Aggregations["services"]; listed {
		t.Error("services is listed, want a disabled table absent")
	}
	if got := report.Aggregations["hosts"].Withheld; got != 1 {
		t.Errorf("hosts.withheld = %d, want 1", got)
	}

	// A named table answers with itself alone.
	w = get(t, srv, config.EntriesPath+"?aggregation=hosts")

	named := struct {
		Aggregations map[string]collector.AggregationEntries `json:"aggregations"`
	}{}
	if err := json.Unmarshal(w.Body.Bytes(), &named); err != nil {
		t.Fatalf("Unmarshal() error = %v, body = %q", err, w.Body.String())
	}
	if _, listed := named.Aggregations["hosts"]; !listed || len(named.Aggregations) != 1 {
		t.Errorf("aggregations = %v, want hosts alone", named.Aggregations)
	}
}

// deadlineRecorder is what ResponseController finds when the handler asks for
// a write deadline.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadline = t
	return nil
}

// TestServer_EntriesBoundTheirWrite pins the write deadline. The in-flight
// bound is one, so a client that stops reading would otherwise hold the only
// slot until it disconnects and no other listing would be served.
func TestServer_EntriesBoundTheirWrite(t *testing.T) {
	t.Parallel()

	srv := entriesServer(t, &stubLister{})

	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, config.EntriesPath, http.NoBody))

	if w.deadline.IsZero() {
		t.Fatal("the listing set no write deadline, want one bounding the response")
	}
	if !w.deadline.After(time.Now()) {
		t.Errorf("write deadline = %v, want it ahead of now", w.deadline)
	}
}

// TestServer_EntriesAdmitOneListingAtATime pins the in-flight bound. The
// listing holds a whole table where a scrape holds Top-K, and no route here
// authenticates, so a second concurrent listing must be refused rather than
// doubling the memory the receiver needs.
func TestServer_EntriesAdmitOneListingAtATime(t *testing.T) {
	t.Parallel()

	lister := &stubLister{entered: make(chan struct{}), release: make(chan struct{})}
	srv := entriesServer(t, lister)

	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, config.EntriesPath, http.NoBody))
		done <- w.Code
	}()

	<-lister.entered

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, config.EntriesPath, http.NoBody))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("the second listing = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}

	close(lister.release)
	if first := <-done; first != http.StatusOK {
		t.Errorf("the first listing = %d, want %d", first, http.StatusOK)
	}
}
