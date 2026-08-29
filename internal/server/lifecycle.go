// Package server provides HTTP server lifecycle management for Prometheus exporters.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/collector"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/flow"
	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// LifecycleManager manages HTTP server startup and graceful shutdown.
type LifecycleManager struct {
	server *http.Server
	cfg    *config.Config
}

// NewLifecycleManager creates a new server lifecycle manager.
func NewLifecycleManager(registry *prometheus.Registry, cfg *config.Config) *LifecycleManager {
	addr := net.JoinHostPort(cfg.Web.ListenAddress, strconv.Itoa(cfg.Web.ListenPort))
	server := New(registry, addr, cfg.Web.TelemetryPath)

	return &LifecycleManager{
		server: server,
		cfg:    cfg,
	}
}

// StartAndServe creates the receiver and the collectors, sets up the server,
// and starts serving. It handles the complete lifecycle from setup to shutdown.
func StartAndServe(ctx context.Context, cfg *config.Config, version string) error {
	slog.Info("Starting xflow-exporter",
		"version", version,
		"listen_address", cfg.Web.ListenAddress,
		"listen_port", cfg.Web.ListenPort,
		"telemetry_path", cfg.Web.TelemetryPath)

	// Bind the flow listeners before anything serves, so a taken port fails
	// startup instead of surfacing as a receiver that never counts a packet.
	recv := receiver.New(cfg.Receiver)
	if err := recv.Listen(); err != nil {
		return err
	}

	dec := decoder.New()

	// Create and setup collector manager
	collectorMgr := collector.NewCollector(cfg)
	collectorMgr.Setup(version)
	collectorMgr.RegisterReceiverCollector(recv)
	collectorMgr.RegisterDecoderCollector(dec)

	// The receiver stops when this context ends, which Run ties to the
	// shutdown signals.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	receiverDone := make(chan struct{})
	go func() {
		defer close(receiverDone)
		recv.Serve(ctx)
	}()

	// Decode workers consume the queue. Records are decoded and accounted,
	// then discarded until the aggregator lands.
	workers := cfg.Receiver.Workers
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	var decodeWG sync.WaitGroup
	for range workers {
		decodeWG.Add(1)
		go func() {
			defer decodeWG.Done()
			decodeLoop(recv, dec)
		}()
	}

	// Create and run server lifecycle manager
	serverMgr := NewLifecycleManager(collectorMgr.Registry(), cfg)
	err := serverMgr.Run(ctx)

	cancel()
	<-receiverDone
	decodeWG.Wait()
	return err
}

// decodeLoop drains the receive queue through the decoder until the queue
// closes. The records slice is reused across datagrams, so a steady worker
// allocates nothing per packet.
func decodeLoop(recv *receiver.Receiver, dec *decoder.Decoder) {
	var records []flow.Record

	for pkt := range recv.Packets() {
		var err error
		records, err = dec.Decode(pkt.Src.Addr(), pkt.Data, records[:0])
		if err != nil {
			slog.Debug("Rejected a flow datagram",
				"exporter", pkt.Src.Addr(), "listener", pkt.Listener, "error", err)
		}
		recv.Release(pkt)
	}
}

// Run starts the HTTP server and handles graceful shutdown.
// It blocks until the server is shut down or an error occurs.
func (lm *LifecycleManager) Run(ctx context.Context) error {
	// Setup graceful shutdown context
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		slog.Info("HTTP server listening", "addr", lm.server.Addr)
		if err := lm.server.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		slog.Info("Shutdown signal received")
	case err := <-errCh:
		return err
	}

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := lm.server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Failed to shutdown HTTP server gracefully", "error", err)
		return err
	}

	slog.Info("HTTP server shutdown complete")
	return nil
}
