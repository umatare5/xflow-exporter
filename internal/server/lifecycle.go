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

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/collector"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/enrich"
	"github.com/umatare5/xflow-exporter/internal/flow"
	"github.com/umatare5/xflow-exporter/internal/receiver"
	"github.com/umatare5/xflow-exporter/internal/remotewrite"
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

	dec := decoder.New(cfg.Parser)

	modules := aggregator.Modules{
		Exporters:    cfg.Collectors.Exporters,
		Hosts:        cfg.Collectors.Hosts,
		Services:     cfg.Collectors.Services,
		ASNs:         cfg.Collectors.ASNs,
		Applications: cfg.Collectors.Applications,
		Countries:    cfg.Collectors.Countries,
		Threats:      cfg.Collectors.Threats,
	}

	// Create and setup collector manager
	collectorMgr := collector.NewCollector(cfg)
	collectorMgr.Setup(version)
	collectorMgr.RegisterReceiverCollector(recv)
	collectorMgr.RegisterDecoderCollector(dec)

	var agg *aggregator.Aggregator
	if modules.Any() {
		agg = aggregator.New(cfg.Aggregation, modules)
		collectorMgr.RegisterFlowCollector(agg, cfg.Collectors, cfg.Aggregation)
	}

	var dist *collector.Distributions
	if cfg.Collectors.Distributions {
		dist = collectorMgr.RegisterDistributions()
	}

	// Enrichment runs before anything reads a record, so a dimension it
	// fills reaches the aggregation tables and the histograms alike. A
	// database that cannot be opened fails startup: an exporter that quietly
	// enriched nothing would be indistinguishable from one whose database
	// knew nothing.
	chain, err := buildEnrichmentChain(cfg.Enrichment)
	if err != nil {
		return err
	}
	if chain.Enabled() {
		collectorMgr.RegisterEnrichmentCollector(chain)
		defer chain.Close()
	}

	// The receiver stops when this context ends, which Run ties to the
	// shutdown signals.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	receiverDone := make(chan struct{})
	go func() {
		defer close(receiverDone)
		recv.Serve(ctx)
	}()

	// The eviction sweep runs for as long as the receiver does.
	aggDone := make(chan struct{})
	go func() {
		defer close(aggDone)
		if agg != nil {
			agg.Run(ctx)
		}
	}()

	// Idle observation domains are swept on the same schedule, so a device
	// that renumbers its domains does not hold its budget forever.
	domainSweepDone := make(chan struct{})
	go func() {
		defer close(domainSweepDone)
		sweepDomains(ctx, dec, cfg.Parser.TemplateTTL)
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
			decodeLoop(recv, dec, chain, agg, dist)
		}()
	}

	// The remote write client reads the same registry a scrape reads, so
	// shipping changes no series and no value.
	remoteDone := make(chan struct{})
	if cfg.RemoteWrite.Enabled() {
		writer, werr := remotewrite.New(cfg.RemoteWrite, collectorMgr.Registry())
		if werr != nil {
			close(remoteDone)
			return werr
		}
		collectorMgr.RegisterRemoteWriteCollector(writer)

		go func() {
			defer close(remoteDone)
			writer.Run(ctx)
		}()
	} else {
		close(remoteDone)
	}

	// Create and run server lifecycle manager
	serverMgr := NewLifecycleManager(collectorMgr.Registry(), cfg)
	err = serverMgr.Run(ctx)

	cancel()
	<-receiverDone
	decodeWG.Wait()
	<-aggDone
	<-domainSweepDone
	<-remoteDone
	return err
}

// buildEnrichmentChain assembles the enabled enrichment sources in the order
// they are applied. Order matters where two sources fill one dimension: the
// first to know wins, and every source leaves a device reading alone.
func buildEnrichmentChain(cfg config.Enrichment) (*enrich.Chain, error) {
	var enrichers []enrich.Enricher

	if cfg.Services {
		enrichers = append(enrichers, enrich.NewServices())
	}
	if cfg.ASNDatabase != "" {
		asn, err := enrich.NewASN(cfg.ASNDatabase)
		if err != nil {
			return nil, err
		}
		enrichers = append(enrichers, asn)
	}
	if cfg.CountryDatabase != "" {
		country, err := enrich.NewCountry(cfg.CountryDatabase)
		if err != nil {
			return nil, err
		}
		enrichers = append(enrichers, country)
	}
	if cfg.Threat.APIKey != "" {
		threat, err := enrich.NewThreat(enrich.ThreatConfig{
			APIKey:    cfg.Threat.APIKey,
			Threshold: cfg.Threat.Threshold,
			CacheTTL:  cfg.Threat.CacheTTL,
			CacheSize: cfg.Threat.CacheSize,
			Timeout:   cfg.Threat.Timeout,
		})
		if err != nil {
			return nil, err
		}
		enrichers = append(enrichers, threat)
	}

	return enrich.NewChain(enrichers...), nil
}

// sweepDomains drops idle observation domains until ctx ends. The interval is
// a quarter of the template TTL, so an idle domain outlives its slot by at
// most that much.
func sweepDomains(ctx context.Context, dec *decoder.Decoder, ttl time.Duration) {
	const sweepDivisor = 4

	interval := ttl / sweepDivisor
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if evicted := dec.SweepDomains(); evicted > 0 {
				slog.Debug("Swept idle observation domains", "evicted", evicted)
			}
		}
	}
}

// decodeLoop drains the receive queue through the decoder into the enabled
// consumers until the queue closes. The records slice is reused across
// datagrams, so a steady worker allocates nothing per packet.
func decodeLoop(
	recv *receiver.Receiver, dec *decoder.Decoder, chain *enrich.Chain,
	agg *aggregator.Aggregator, dist *collector.Distributions,
) {
	var records []flow.Record

	for pkt := range recv.Packets() {
		var err error
		records, err = dec.Decode(pkt.Src.Addr(), pkt.Data, records[:0])
		if err != nil {
			slog.Debug("Rejected a flow datagram",
				"exporter", pkt.Src.Addr(), "listener", pkt.Listener, "error", err)
		}
		recv.Release(pkt)

		chain.Enrich(records)

		if agg != nil {
			agg.Ingest(records)
		}
		if dist != nil {
			dist.Observe(records)
		}
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
