// Package remotewrite ships the exporter's own registry to a remote endpoint,
// for the deployments a Prometheus scrape cannot reach.
package remotewrite

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"time"

	"github.com/prometheus/client_golang/exp/api/remote"
	writev2 "github.com/prometheus/client_golang/exp/api/remote/genproto/v2"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// Writer gathers the registry on an interval and ships it to a remote
// endpoint. It is a second reader of the same registry a scrape reads, so
// enabling it changes no series and no value.
type Writer struct {
	api      *remote.API
	gatherer prometheus.Gatherer
	interval time.Duration

	symbols *symbolTable
	stats   *Stats

	// now stamps the samples, pinned by tests.
	now func() time.Time
}

// New creates a writer for the configured endpoint.
//
// The client takes the base URL and the request path separately, so a
// configured URL carrying a path is split rather than passed whole: passing
// it whole silently posts to the client's own default path, which answers 404
// on every endpoint that expects the configured one.
func New(cfg config.RemoteWrite, gatherer prometheus.Gatherer) (*Writer, error) {
	base, path, err := splitEndpoint(cfg.URL)
	if err != nil {
		return nil, err
	}

	options := []remote.APIOption{
		remote.WithAPIHTTPClient(newHTTPClient(cfg)),
		remote.WithAPILogger(slog.Default()),
	}
	if path != "" {
		options = append(options, remote.WithAPIPath(path))
	}

	api, err := remote.NewAPI(base, options...)
	if err != nil {
		return nil, fmt.Errorf("building the remote write client for %q: %w", cfg.URL, err)
	}

	return &Writer{
		api:      api,
		gatherer: gatherer,
		interval: cfg.Interval,
		symbols:  newSymbolTable(),
		stats:    &Stats{},
		now:      time.Now,
	}, nil
}

// splitEndpoint separates the configured URL into the base the client dials
// and the path it posts to.
func splitEndpoint(endpoint string) (base, path string, err error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid remote write URL %q: %w", endpoint, err)
	}

	path = parsed.Path
	parsed.Path = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), path, nil
}

// Stats returns the send statistics for the metrics collector.
func (w *Writer) Stats() *Stats {
	return w.stats
}

// Run ships the registry every interval until ctx ends.
func (w *Writer) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.send(ctx); err != nil {
				slog.Error("Failed to ship metrics to the remote endpoint", "error", err)
			}
		}
	}
}

// send gathers the registry once and writes it.
func (w *Writer) send(ctx context.Context) error {
	families, err := w.gatherer.Gather()
	if err != nil {
		w.stats.failures.Add(1)
		return fmt.Errorf("gathering the registry: %w", err)
	}

	req := w.build(families)
	if len(req.Timeseries) == 0 {
		return nil
	}

	if _, err := w.api.Write(ctx, remote.WriteV2MessageType, req); err != nil {
		w.stats.failures.Add(1)
		return fmt.Errorf("writing to the remote endpoint: %w", err)
	}

	w.stats.sends.Add(1)
	w.stats.samples.Add(uint64(len(req.Timeseries))) //nolint:gosec // A series count is never negative.
	w.stats.lastSuccessUnixNano.Store(w.now().UnixNano())
	return nil
}

// build converts the gathered families into one write request. The symbol
// table is reused across sends, reset rather than reallocated.
func (w *Writer) build(families []*dto.MetricFamily) *writev2.Request {
	w.symbols.reset()

	timestamp := w.now().UnixMilli()
	series := make([]*writev2.TimeSeries, 0, len(families))

	for _, family := range families {
		for _, metric := range family.GetMetric() {
			value, ok := sampleValue(family.GetType(), metric)
			if !ok {
				// A histogram or summary carries no single value, and Remote
				// Write 2.0 encodes it as its own message. Skipping it is
				// visible in the series count rather than silent corruption.
				continue
			}

			series = append(series, &writev2.TimeSeries{
				LabelsRefs: w.symbols.internPairs(labelsOf(family.GetName(), metric)),
				Samples:    []*writev2.Sample{{Value: value, Timestamp: timestamp}},
			})
		}
	}

	return w.symbols.request(series)
}

// sampleValue reads the one value a family carries, reporting false for the
// types that carry none.
func sampleValue(kind dto.MetricType, metric *dto.Metric) (float64, bool) {
	switch kind {
	case dto.MetricType_COUNTER:
		return metric.GetCounter().GetValue(), true
	case dto.MetricType_GAUGE:
		return metric.GetGauge().GetValue(), true
	case dto.MetricType_UNTYPED:
		return metric.GetUntyped().GetValue(), true
	case dto.MetricType_HISTOGRAM, dto.MetricType_SUMMARY, dto.MetricType_GAUGE_HISTOGRAM:
		return 0, false
	default:
		return 0, false
	}
}

// labelsOf builds one series' label set, sorted by name as the specification
// requires. The metric name travels as the __name__ label.
func labelsOf(name string, metric *dto.Metric) []labelPair {
	pairs := make([]labelPair, 0, len(metric.GetLabel())+1)
	pairs = append(pairs, labelPair{name: "__name__", value: name})

	for _, label := range metric.GetLabel() {
		pairs = append(pairs, labelPair{name: label.GetName(), value: label.GetValue()})
	}

	sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	return pairs
}
