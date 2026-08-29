package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/server"
)

func TestNewLifecycleManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "creates lifecycle manager with default config",
			cfg: &config.Config{
				Web: config.Web{
					ListenAddress: "0.0.0.0",
					ListenPort:    8080,
					TelemetryPath: config.DefaultTelemetryPath,
				},
			},
		},
		{
			name: "creates lifecycle manager with custom address",
			cfg: &config.Config{
				Web: config.Web{
					ListenAddress: "127.0.0.1",
					ListenPort:    9090,
					TelemetryPath: config.DefaultTelemetryPath,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := prometheus.NewRegistry()
			mgr := server.NewLifecycleManager(registry, tt.cfg, nil)

			if mgr == nil {
				t.Fatal("NewLifecycleManager() returned nil")
			}

			// Test that the manager can be created without errors
			// Since fields are unexported, we can only test the public API
		})
	}
}

func TestLifecycleManager_RunWithImmediateCancel(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Web: config.Web{
			ListenAddress: "127.0.0.1",
			ListenPort:    0, // Use port 0 to get an available port
			TelemetryPath: config.DefaultTelemetryPath,
		},
	}

	registry := prometheus.NewRegistry()
	mgr := server.NewLifecycleManager(registry, cfg, nil)

	// Create a context that's immediately canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Run should return without error due to immediate cancellation
	err := mgr.Run(ctx)
	if err != nil {
		t.Errorf("LifecycleManager.Run() with canceled context returned error: %v", err)
	}
}

func TestLifecycleManager_RunWithTimeout(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Web: config.Web{
			ListenAddress: "127.0.0.1",
			ListenPort:    0, // Use port 0 to get an available port
			TelemetryPath: config.DefaultTelemetryPath,
		},
	}

	registry := prometheus.NewRegistry()
	mgr := server.NewLifecycleManager(registry, cfg, nil)

	// Create a context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Run should return without error due to timeout
	err := mgr.Run(ctx)
	if err != nil {
		t.Errorf("LifecycleManager.Run() with timeout returned error: %v", err)
	}
}

func TestStartAndServe_WithImmediateCancel(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Web: config.Web{
			ListenAddress: "127.0.0.1",
			ListenPort:    0, // Use port 0 to get an available port
			TelemetryPath: config.DefaultTelemetryPath,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	if err := server.StartAndServe(ctx, cfg, "test-version"); err != nil {
		t.Errorf("StartAndServe() with canceled context returned error: %v", err)
	}
}
