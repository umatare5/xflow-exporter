// Package collector provides registry management and collector registration.
package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/umatare5/xflow-exporter/internal/config"
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
