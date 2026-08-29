// This file holds the decode self-monitoring collector.

package collector

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/decoder"
)

// DecoderSource is what this collector reads from the decode stage.
type DecoderSource interface {
	Stats() *decoder.Stats
	Domains() []decoder.DomainSnapshot
	DomainsRefused() uint64
	VendorStringsRefused() uint64
	ApplicationsRefused() uint64
	ExportersRefused() uint64
}

// DecoderCollector reports what the decoders made of the received datagrams.
// Exporter devices appear on their first datagram: a push protocol cannot
// know its senders in advance, so nothing is seeded per device.
type DecoderCollector struct {
	src DecoderSource

	flowsDesc    *prometheus.Desc
	errorsDesc   *prometheus.Desc
	lastFlowDesc *prometheus.Desc

	templatesDesc        *prometheus.Desc
	seqMissedDesc        *prometheus.Desc
	samplingDesc         *prometheus.Desc
	domainsRefusedDesc   *prometheus.Desc
	exportersRefusedDesc *prometheus.Desc
	stringsRefusedDesc   *prometheus.Desc
	appsRefusedDesc      *prometheus.Desc
}

// NewDecoderCollector creates a collector reporting decode outcomes.
func NewDecoderCollector(src DecoderSource) *DecoderCollector {
	return &DecoderCollector{
		src: src,
		flowsDesc: prometheus.NewDesc(
			"xflow_flows_total",
			"Flow records decoded per exporter and version since process start",
			[]string{labelExporter, labelVersion}, nil,
		),
		errorsDesc: prometheus.NewDesc(
			"xflow_decode_errors_total",
			"Datagrams rejected per exporter, version and reason since process start",
			[]string{labelExporter, labelVersion, labelReason}, nil,
		),
		lastFlowDesc: prometheus.NewDesc(
			"xflow_last_flow_timestamp_seconds",
			"Unix time the exporter's last datagram decoded, absent until one has",
			[]string{labelExporter}, nil,
		),
		templatesDesc: prometheus.NewDesc(
			"xflow_templates",
			"Unexpired templates held per exporter, protocol, observation domain and kind",
			[]string{labelExporter, labelVersion, labelODID, labelType}, nil,
		),
		seqMissedDesc: prometheus.NewDesc(
			"xflow_sequence_missed_total",
			"Export packets the sequence numbers say were lost, per protocol and observation domain",
			[]string{labelExporter, labelVersion, labelODID}, nil,
		),
		samplingDesc: prometheus.NewDesc(
			"xflow_sampling_rate",
			"Packet sampling rate the domain's options declared, absent until one arrives",
			[]string{labelExporter, labelVersion, labelODID}, nil,
		),
		domainsRefusedDesc: prometheus.NewDesc(
			"xflow_domains_refused_total",
			"Datagrams discarded since process start, the exporter being at its observation domain budget",
			nil, nil,
		),
		stringsRefusedDesc: prometheus.NewDesc(
			"xflow_vendor_strings_refused_total",
			"Vendor string fields refused since process start, counted per occurrence rather than per string",
			nil, nil,
		),
		appsRefusedDesc: prometheus.NewDesc(
			"xflow_applications_refused_total",
			"Application announcements refused since process start, the exporter being at its application budget",
			nil, nil,
		),
		exportersRefusedDesc: prometheus.NewDesc(
			"xflow_exporters_refused_total",
			"Datagrams left unattributed since process start, the process being at its exporter budget",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *DecoderCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.flowsDesc
	ch <- c.errorsDesc
	ch <- c.lastFlowDesc
	ch <- c.templatesDesc
	ch <- c.seqMissedDesc
	ch <- c.samplingDesc
	ch <- c.domainsRefusedDesc
	ch <- c.stringsRefusedDesc
	ch <- c.appsRefusedDesc
	ch <- c.exportersRefusedDesc
}

// Collect implements prometheus.Collector by reading the decode counters.
func (c *DecoderCollector) Collect(ch chan<- prometheus.Metric) {
	const nanosPerSecond = 1e9

	for _, snap := range c.src.Stats().Snapshot() {
		exporter := snap.Exporter.String()

		for _, flows := range snap.Flows {
			ch <- prometheus.MustNewConstMetric(
				c.flowsDesc, prometheus.CounterValue,
				float64(flows.Count), exporter, flows.Version.String())
		}
		for _, errs := range snap.Errors {
			ch <- prometheus.MustNewConstMetric(
				c.errorsDesc, prometheus.CounterValue,
				float64(errs.Count), exporter, errs.Version.String(), errs.Reason)
		}

		// A device that never decoded has no last-flow instant: publishing a
		// zero would read as a flow in 1970.
		if snap.LastFlowUnixNano > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.lastFlowDesc, prometheus.GaugeValue,
				float64(snap.LastFlowUnixNano)/nanosPerSecond, exporter)
		}
	}

	c.collectDomains(ch)

	// Seeded at zero: a first refusal must read as a rise on an existing
	// series rather than as a series appearing from nothing.
	ch <- prometheus.MustNewConstMetric(
		c.domainsRefusedDesc, prometheus.CounterValue, float64(c.src.DomainsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.stringsRefusedDesc, prometheus.CounterValue, float64(c.src.VendorStringsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.appsRefusedDesc, prometheus.CounterValue, float64(c.src.ApplicationsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.exportersRefusedDesc, prometheus.CounterValue, float64(c.src.ExportersRefused()))
}

// The template kinds published in the type label.
const (
	templateKindData    = "template"
	templateKindOptions = "options_template"
)

// collectDomains reports the per-observation-domain state.
func (c *DecoderCollector) collectDomains(ch chan<- prometheus.Metric) {
	for _, domain := range c.src.Domains() {
		exporter := domain.Exporter.String()
		version := domain.Version.String()
		odid := strconv.FormatUint(uint64(domain.ODID), 10)

		ch <- prometheus.MustNewConstMetric(
			c.templatesDesc, prometheus.GaugeValue,
			float64(domain.Templates), exporter, version, odid, templateKindData)
		ch <- prometheus.MustNewConstMetric(
			c.templatesDesc, prometheus.GaugeValue,
			float64(domain.OptionsTemplates), exporter, version, odid, templateKindOptions)
		ch <- prometheus.MustNewConstMetric(
			c.seqMissedDesc, prometheus.CounterValue,
			float64(domain.SequenceMissed), exporter, version, odid)

		// A domain that has not declared a rate has no series: a zero here
		// would read as sampling switched off rather than unknown.
		if domain.SamplingRate > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.samplingDesc, prometheus.GaugeValue,
				float64(domain.SamplingRate), exporter, version, odid)
		}
	}
}
