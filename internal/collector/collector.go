// Package collector provides registry management and collector registration.
package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/enrich"
)

// Collector manages Prometheus collectors and registry.
type Collector struct {
	registry *prometheus.Registry
	cfg      *config.Config
}

// NewCollector creates a new collector manager.
func NewCollector(cfg *config.Config) *Collector {
	return &Collector{
		registry: prometheus.NewRegistry(),
		cfg:      cfg,
	}
}

// Registry returns the Prometheus registry managed by this collector.
func (c *Collector) Registry() *prometheus.Registry {
	return c.registry
}

// Setup configures and registers all collectors based on configuration.
func (c *Collector) Setup(version string) {
	c.RegisterBuildInfo(version)
	c.RegisterSystemCollectors()
}

// RegisterBuildInfo registers the build information metric.
func (c *Collector) RegisterBuildInfo(version string) {
	buildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xflow_build_info",
			Help: "Build information for the xflow exporter.",
		},
		[]string{"version"},
	)
	buildInfo.WithLabelValues(version).Set(1)
	c.registry.MustRegister(buildInfo)
}

// RegisterReceiverCollector registers the receiver self-monitoring collector.
func (c *Collector) RegisterReceiverCollector(src ReceiverSource) {
	c.registry.MustRegister(NewSafeCollector(NewReceiverCollector(src), "Receiver"))
	slog.Debug("Registered receiver collector")
}

// RegisterDecoderCollector registers the decode self-monitoring collector.
func (c *Collector) RegisterDecoderCollector(src DecoderSource) {
	c.registry.MustRegister(NewSafeCollector(NewDecoderCollector(src), "Decoder"))
	slog.Debug("Registered decoder collector")
}

// RegisterFlowCollector registers the aggregation table collector.
func (c *Collector) RegisterFlowCollector(
	src FlowSource, modules config.Collectors, agg config.Aggregation, asnNames func(uint32) (string, bool),
) {
	c.registry.MustRegister(NewSafeCollector(NewFlowCollector(src, modules, agg, asnNames), "Flow"))
	slog.Debug("Registered flow collector")
}

// RegisterDistributions registers the flow distribution histograms and
// returns them for the ingest path to observe.
func (c *Collector) RegisterDistributions() *Distributions {
	d := NewDistributions()
	d.Register(c.registry)
	slog.Debug("Registered distribution histograms")
	return d
}

// RegisterEnrichmentCollector registers the enrichment self-monitoring collector.
func (c *Collector) RegisterEnrichmentCollector(src enrich.Snapshotter, threat *enrich.Threat) {
	c.registry.MustRegister(NewSafeCollector(NewEnrichmentCollector(src, threat), "Enrichment"))
	slog.Debug("Registered enrichment collector")
}

// RegisterRemoteWriteCollector registers the remote write self-monitoring collector.
func (c *Collector) RegisterRemoteWriteCollector(src RemoteWriteSource) {
	c.registry.MustRegister(NewSafeCollector(NewRemoteWriteCollector(src), "RemoteWrite"))
	slog.Debug("Registered remote write collector")
}

// RegisterSystemCollectors registers Go and process collectors conditionally.
func (c *Collector) RegisterSystemCollectors() {
	if c.cfg.InternalCollector.EnableGoCollector {
		c.registry.MustRegister(collectors.NewGoCollector())
		slog.Debug("Registered Go collector")
	}
	if c.cfg.InternalCollector.EnableProcessCollector {
		c.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		slog.Debug("Registered process collector")
	}
}
