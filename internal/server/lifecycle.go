// Package server provides HTTP server lifecycle management for Prometheus exporters.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	server   *http.Server
	cfg      *config.Config
	reloader Reloader
}

// NewLifecycleManager creates a new server lifecycle manager. reloader is
// exposed on the management endpoint only when the lifecycle flag is set,
// and it is what a SIGHUP drives as well.
func NewLifecycleManager(registry *prometheus.Registry, cfg *config.Config, reloader Reloader) *LifecycleManager {
	addr := net.JoinHostPort(cfg.Web.ListenAddress, strconv.Itoa(cfg.Web.ListenPort))

	var exposed Reloader
	if cfg.Web.EnableLifecycle {
		exposed = reloader
	}

	return &LifecycleManager{
		server:   New(registry, addr, cfg.Web.TelemetryPath, exposed),
		cfg:      cfg,
		reloader: reloader,
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
		Destinations: cfg.Collectors.Destinations,
		TCPFlags:     cfg.Collectors.TCPFlags,
		DSCP:         cfg.Collectors.DSCP,
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

	var dist *collector.Distributions
	if cfg.Collectors.Distributions {
		dist = collectorMgr.RegisterDistributions()
	}

	// Enrichment runs before anything reads a record, so a dimension it
	// fills reaches the aggregation tables and the histograms alike. A
	// database that cannot be opened fails startup: an exporter that quietly
	// enriched nothing would be indistinguishable from one whose database
	// knew nothing.
	chain, threat, asn, err := buildEnrichmentChain(cfg.Enrichment)
	if err != nil {
		return err
	}
	if chain.Enabled() {
		collectorMgr.RegisterEnrichmentCollector(chain, threat)
		defer chain.Close()
	}

	// Registered after the chain, which is what can name an autonomous
	// system. Without an ASN database the naming series is absent rather
	// than empty.
	var asnNames func(uint32) (string, bool)
	if asn != nil {
		asnNames = asn.Organization
	}
	if modules.Any() {
		agg = aggregator.New(cfg.Aggregation, modules)
		collectorMgr.RegisterFlowCollector(agg, cfg.Collectors, cfg.Aggregation, asnNames)
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
	serverMgr := NewLifecycleManager(collectorMgr.Registry(), cfg, chain)
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
func buildEnrichmentChain(cfg config.Enrichment) (*enrich.Chain, *enrich.Threat, *enrich.ASN, error) {
	var enrichers []enrich.Enricher
	var threat *enrich.Threat
	var asn *enrich.ASN

	if cfg.Services {
		enrichers = append(enrichers, enrich.NewServices())
	}
	if cfg.ASNDatabase != "" {
		opened, err := enrich.NewASN(cfg.ASNDatabase)
		if err != nil {
			return nil, nil, nil, err
		}
		asn = opened
		enrichers = append(enrichers, asn)
	}
	if cfg.CountryDatabase != "" {
		country, err := enrich.NewCountry(cfg.CountryDatabase)
		if err != nil {
			return nil, nil, nil, err
		}
		enrichers = append(enrichers, country)
	}
	if len(cfg.ThreatFiles) > 0 {
		loaded, err := enrich.NewThreat(cfg.ThreatFiles)
		if err != nil {
			return nil, nil, nil, err
		}
		threat = loaded
		enrichers = append(enrichers, threat)
	}

	return enrich.NewChain(enrichers...), threat, asn, nil
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
			// Only once the exporter budget is reached, so a device that has
			// simply gone quiet keeps the freshness series that says so.
			if evicted := dec.SweepExporters(); evicted > 0 {
				slog.Debug("Swept idle exporters", "evicted", evicted)
			}
		}
	}
}

// watchHangup reloads the enrichment sources on every SIGHUP until ctx ends,
// returning the function that releases the signal registration.
func (lm *LifecycleManager) watchHangup(ctx context.Context) func() {
	if lm.reloader == nil {
		return func() {}
	}

	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)

	// stop releases the watcher without waiting on ctx. The caller defers
	// this alongside the cancel that ends ctx, and defers run last in first:
	// waiting on ctx here would wait for a cancel still queued behind it, so
	// a server that fails to listen would hang rather than report why.
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-hangup:
				if err := lm.reloader.Reload(); err != nil {
					slog.Error("Failed to reload on SIGHUP", "error", err)
					continue
				}
				slog.Info("Reloaded the enrichment sources on SIGHUP")
			}
		}
	}()

	return func() {
		signal.Stop(hangup)
		close(stop)
		<-done
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

	// A SIGHUP reloads the enrichment sources, which is the signal
	// Prometheus reloads on and what an operator reaches for when the
	// management endpoint is not exposed.
	stopHangup := lm.watchHangup(ctx)
	defer stopHangup()

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
