package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/server"
)

// probeRegistry holds one named series so a response can be told apart from the
// landing page by its body rather than by its status, which is 200 either way.
func probeRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "xflow_probe", Help: "probe"}))
	return reg
}

func TestServer_ServesMetricsAtTheConfiguredPath(t *testing.T) {
	t.Parallel()

	const telemetryPath = "/wnc-metrics"

	srv := server.New(probeRegistry(t), ":8080", telemetryPath, nil)

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, telemetryPath, http.NoBody))
	if body := w.Body.String(); !strings.Contains(body, "xflow_probe") {
		t.Errorf("%s body = %q, want the registry exposition", telemetryPath, body)
	}

	w = httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, config.DefaultTelemetryPath, http.NoBody))
	if strings.Contains(w.Body.String(), "xflow_probe") {
		t.Errorf("%s serves metrics, want only the configured path to", config.DefaultTelemetryPath)
	}

	w = httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if want := `<a href="` + telemetryPath + `">Metrics</a>`; !strings.Contains(w.Body.String(), want) {
		t.Errorf("landing page body = %q, want it to link %s", w.Body.String(), want)
	}
}

// TestServer_ServesMetricsAtTheRoot covers the only value Validate accepts that
// would register a second handler on a pattern already taken.
func TestServer_ServesMetricsAtTheRoot(t *testing.T) {
	t.Parallel()

	srv := server.New(probeRegistry(t), ":8080", "/", nil)

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if body := w.Body.String(); !strings.Contains(body, "xflow_probe") {
		t.Errorf("/ body = %q, want the registry exposition", body)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
	}{
		{
			name: "creates server with standard address",
			addr: ":8080",
		},
		{
			name: "creates server with custom address",
			addr: "localhost:9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv := server.New(reg, tt.addr, config.DefaultTelemetryPath, nil)

			if srv == nil {
				t.Fatal("New() returned nil server")
			}

			if srv.Addr != tt.addr {
				t.Errorf("New() addr = %v, want %v", srv.Addr, tt.addr)
			}

			if srv.Handler == nil {
				t.Error("New() handler is nil")
			}

			expectedTimeout := 30 * time.Second
			if srv.ReadHeaderTimeout != expectedTimeout {
				t.Errorf("New() ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, expectedTimeout)
			}
		})
	}
}

func TestServer_MetricsEndpoint(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv := server.New(reg, ":8080", config.DefaultTelemetryPath, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	w := httptest.NewRecorder()

	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/metrics status = %v, want %v", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType == "" {
		t.Error("/metrics missing Content-Type header")
	}
}

func TestServer_HealthzEndpoint(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv := server.New(reg, ":8080", config.DefaultTelemetryPath, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()

	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/healthz status = %v, want %v", w.Code, http.StatusOK)
	}

	expectedContentType := "text/plain; charset=utf-8"
	if contentType := w.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("/healthz Content-Type = %v, want %v", contentType, expectedContentType)
	}

	expectedBody := "OK\n"
	if body := w.Body.String(); body != expectedBody {
		t.Errorf("/healthz body = %v, want %v", body, expectedBody)
	}
}

func TestServer_RootEndpoint(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv := server.New(reg, ":8080", config.DefaultTelemetryPath, nil)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/ status = %v, want %v", w.Code, http.StatusOK)
	}

	expectedContentType := "text/html; charset=utf-8"
	if contentType := w.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("/ Content-Type = %v, want %v", contentType, expectedContentType)
	}

	body := w.Body.String()
	expectedStrings := []string{
		"<title>xflow-exporter</title>",
		"<h1>xflow-exporter</h1>",
		`<a href="/metrics">Metrics</a>`,
		`<a href="/healthz">Health Check</a>`,
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(body, expected) {
			t.Errorf("/ body missing expected content: %v", expected)
		}
	}
}

func TestServer_NotFoundEndpoint(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv := server.New(reg, ":8080", config.DefaultTelemetryPath, nil)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", http.NoBody)
	w := httptest.NewRecorder()

	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/nonexistent status = %v, want %v", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, "xflow-exporter") {
		t.Error("/nonexistent should serve root page content")
	}
}

func TestServer_HTTPMethods(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv := server.New(reg, ":8080", config.DefaultTelemetryPath, nil)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/healthz", http.NoBody)
			w := httptest.NewRecorder()

			srv.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("/healthz %s status = %v, want %v", method, w.Code, http.StatusOK)
			}
		})
	}
}

// TestServer_MetricsHonoursTheNameFilter pins the one control a reader has
// over what crosses the wire. The name[] parameter comes from promhttp rather
// than from this package, so nothing here would otherwise notice a handler
// wrapped for logging or authentication dropping the query string -- and the
// bundled scrape configuration tells an operator the control is there.
func TestServer_MetricsHonoursTheNameFilter(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "xflow_wanted", Help: "wanted"}))
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "xflow_unwanted", Help: "unwanted"}))
	srv := server.New(reg, ":8080", config.DefaultTelemetryPath, nil)

	req := httptest.NewRequest(http.MethodGet, config.DefaultTelemetryPath+"?name%5B%5D=xflow_wanted", http.NoBody)
	req.Header.Set("Accept", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !strings.Contains(body, "xflow_wanted") {
		t.Errorf("body does not carry the selected family:\n%s", body)
	}
	if strings.Contains(body, "xflow_unwanted") {
		t.Errorf("body carries a family name[] did not select:\n%s", body)
	}
	if !strings.HasSuffix(body, "# EOF\n") {
		t.Errorf("body does not end in the OpenMetrics terminator:\n%s", body)
	}
}
