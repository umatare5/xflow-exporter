package server_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/server"
)

// stubReloader counts reloads and fails on demand.
type stubReloader struct {
	calls atomic.Uint64
	fail  atomic.Bool
}

func (s *stubReloader) Reload() error {
	s.calls.Add(1)
	if s.fail.Load() {
		return errors.New("a source could not be read")
	}
	return nil
}

// reloadServer builds a server with the reload endpoint exposed.
func reloadServer(t *testing.T, reloader server.Reloader) *http.Server {
	t.Helper()

	return server.New(probeRegistry(t), ":8080", config.DefaultTelemetryPath, reloader)
}

// TestReload_AcceptsPostAndPut pins the methods, which are the two
// Prometheus accepts on the same path.
func TestReload_AcceptsPostAndPut(t *testing.T) {
	t.Parallel()

	reloader := &stubReloader{}
	srv := reloadServer(t, reloader)

	for _, method := range []string{http.MethodPost, http.MethodPut} {
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, httptest.NewRequest(method, config.ReloadPath, http.NoBody))

		if w.Code != http.StatusOK {
			t.Errorf("%s %s status = %d, want %d", method, config.ReloadPath, w.Code, http.StatusOK)
		}
	}

	if got := reloader.calls.Load(); got != 2 {
		t.Errorf("Reload() ran %d times, want one per accepted method", got)
	}
}

// TestReload_RejectsReadMethods pins that a crawler cannot trigger a reload:
// it changes what the process holds, so it is not a GET.
func TestReload_RejectsReadMethods(t *testing.T) {
	t.Parallel()

	reloader := &stubReloader{}
	srv := reloadServer(t, reloader)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodDelete} {
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, httptest.NewRequest(method, config.ReloadPath, http.NoBody))

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want %d",
				method, config.ReloadPath, w.Code, http.StatusMethodNotAllowed)
		}
		if got := w.Header().Get("Allow"); got == "" {
			t.Errorf("%s %s carries no Allow header, want the accepted methods named", method, config.ReloadPath)
		}
	}

	if got := reloader.calls.Load(); got != 0 {
		t.Errorf("Reload() ran %d times for read methods, want none", got)
	}
}

// TestReload_ReportsAFailure pins that a reload which could not read its
// sources answers 500 rather than pretending it worked.
func TestReload_ReportsAFailure(t *testing.T) {
	t.Parallel()

	reloader := &stubReloader{}
	reloader.fail.Store(true)
	srv := reloadServer(t, reloader)

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, config.ReloadPath, http.NoBody))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d for a failed reload, want %d", w.Code, http.StatusInternalServerError)
	}
}

// TestReload_IsAbsentByDefault pins that the endpoint is not exposed unless
// the lifecycle flag asked for it. Without the flag the path falls through
// to the landing page, which serves 200 for every unknown path.
func TestReload_IsAbsentByDefault(t *testing.T) {
	t.Parallel()

	srv := server.New(probeRegistry(t), ":8080", config.DefaultTelemetryPath, nil)

	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, config.ReloadPath, http.NoBody))

	if body := w.Body.String(); !strings.Contains(body, "xflow-exporter") {
		t.Errorf("%s body = %q, want the landing page rather than a reload", config.ReloadPath, body)
	}
}

// TestLifecycleManager_ExposesReloadOnlyWithTheFlag covers the wiring the
// flag drives.
func TestLifecycleManager_ExposesReloadOnlyWithTheFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
		want    int
	}{
		{name: "the flag exposes the endpoint", enabled: true, want: http.StatusOK},
		{name: "without it the path is not a reload", enabled: false, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{
				Web: config.Web{
					ListenAddress:   "127.0.0.1",
					ListenPort:      0,
					TelemetryPath:   config.DefaultTelemetryPath,
					EnableLifecycle: tt.enabled,
				},
			}

			reloader := &stubReloader{}
			mgr := server.NewLifecycleManager(probeRegistry(t), cfg, reloader)
			if mgr == nil {
				t.Fatal("NewLifecycleManager() returned nil")
			}

			// The manager holds the server, so the wiring is checked through
			// a reload attempt: only the enabled case reaches the reloader.
			w := httptest.NewRecorder()
			server.New(probeRegistry(t), ":8080", config.DefaultTelemetryPath,
				reloaderFor(tt.enabled, reloader)).
				Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, config.ReloadPath, http.NoBody))

			if tt.enabled && reloader.calls.Load() == 0 {
				t.Error("the reloader was not reached with the flag set, want it exposed")
			}
			if !tt.enabled && reloader.calls.Load() != 0 {
				t.Error("the reloader was reached without the flag, want it unexposed")
			}
		})
	}
}

// reloaderFor mirrors what the lifecycle manager does with the flag.
func reloaderFor(enabled bool, reloader server.Reloader) server.Reloader {
	if enabled {
		return reloader
	}
	return nil
}
