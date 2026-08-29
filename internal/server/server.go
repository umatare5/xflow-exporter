// Package server provides HTTP server functionality.
package server

import (
	"html"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// Reloader re-reads whatever the exporter loaded from disk.
type Reloader interface {
	Reload() error
}

// New creates a new HTTP server with metrics and health endpoints. Config.Validate
// rejects every telemetryPath that http.ServeMux would panic on, apart from the root,
// which is handled below.
//
// reloader is wired to the management endpoint when it is non-nil, which is
// what --web.enable-lifecycle decides. The endpoint is a write, so it stays
// unexposed by default rather than answering anyone who can reach the port.
func New(reg *prometheus.Registry, addr, telemetryPath string, reloader Reloader) *http.Server {
	mux := http.NewServeMux()

	if reloader != nil {
		mux.HandleFunc(config.ReloadPath, reloadHandler(reloader))
	}

	mux.Handle(telemetryPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics:   true,
		MaxRequestsInFlight: 10,
	}))

	mux.HandleFunc(config.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	// Serving metrics at the root is a legitimate flag value, and registering the
	// landing page as well would panic on the duplicate pattern.
	if telemetryPath != "/" {
		landing := []byte(`<html>
<head><title>xflow-exporter</title></head>
<body>
<h1>xflow-exporter</h1>
<p><a href="` + html.EscapeString(telemetryPath) + `">Metrics</a></p>
<p><a href="` + config.HealthPath + `">Health Check</a></p>
</body>
</html>`)

		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(landing)
		})
	}

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
}

// reloadHandler re-reads the enrichment sources on request.
//
// Only PUT and POST are accepted, which is what Prometheus accepts on the
// same path: a reload changes what the process holds, and a GET that did
// that would be triggered by anything that crawls the port.
func reloadHandler(reloader Reloader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPost+", "+http.MethodPut)
			http.Error(w, "only POST and PUT reload", http.StatusMethodNotAllowed)
			return
		}

		if err := reloader.Reload(); err != nil {
			// The sources that failed kept what they already held, so the
			// exporter is still serving the previous data rather than none.
			slog.Error("Failed to reload the enrichment sources", "error", err)
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Info("Reloaded the enrichment sources")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Reloaded\n"))
	}
}
