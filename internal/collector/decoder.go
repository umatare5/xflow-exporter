// This file holds the decode self-monitoring collector.

package collector

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// DecoderSource is what this collector reads from the decode stage.
type DecoderSource interface {
	Stats() *decoder.Stats
	SamplersRefused() uint64
	Domains() []decoder.DomainSnapshot
	DomainsRefused() uint64
	Samplers() []decoder.SamplerSnapshot
	DeclarationsRefused() uint64
	VendorStringsRefused() uint64
	ApplicationsRefused() uint64
	ExportersRefused() uint64
}

// DecoderCollector reports what the decoders made of the received datagrams.
// Exporter devices appear on their first datagram: a push protocol cannot
// know its senders in advance, so nothing is seeded per device.
type DecoderCollector struct {
	src DecoderSource

	flowsDesc        *prometheus.Desc
	errorsDesc       *prometheus.Desc
	lastFlowDesc     *prometheus.Desc
	lastDatagramDesc *prometheus.Desc

	templatesDesc        *prometheus.Desc
	samplePoolDesc       *prometheus.Desc
	samplesDroppedDesc   *prometheus.Desc
	samplersRefusedDesc  *prometheus.Desc
	seqMissedDesc        *prometheus.Desc
	samplingDesc         *prometheus.Desc
	samplerRateDesc      *prometheus.Desc
	declRefusedDesc      *prometheus.Desc
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
			"Unix time the exporter's last flow record decoded, absent until one has",
			[]string{labelExporter}, nil,
		),
		lastDatagramDesc: prometheus.NewDesc(
			"xflow_last_datagram_timestamp_seconds",
			"Unix time the exporter's last datagram arrived, absent until one has",
			[]string{labelExporter}, nil,
		),
		templatesDesc: prometheus.NewDesc(
			"xflow_templates",
			"Unexpired templates held per exporter, protocol, observation domain and kind",
			[]string{labelExporter, labelVersion, labelODID, labelType}, nil,
		),
		samplePoolDesc: prometheus.NewDesc(
			"xflow_sample_pool_packets_total",
			"Packets the sFlow samplers of one domain could have sampled, absent for v9 and IPFIX",
			[]string{labelExporter, labelVersion, labelODID}, nil,
		),
		samplesDroppedDesc: prometheus.NewDesc(
			"xflow_samples_dropped_total",
			"Flow samples the sFlow agent of one domain could not send, absent for v9 and IPFIX",
			[]string{labelExporter, labelVersion, labelODID}, nil,
		),
		samplersRefusedDesc: prometheus.NewDesc(
			"xflow_samplers_refused_total",
			"Flow samples left untracked since process start, their domain being at its sampler budget",
			nil, nil,
		),
		seqMissedDesc: prometheus.NewDesc(
			"xflow_sequence_missed_total",
			"Packets on v9 and sFlow, or records on v5, v8 and IPFIX, the sequence numbers say were lost, per domain",
			[]string{labelExporter, labelVersion, labelODID}, nil,
		),
		samplingDesc: prometheus.NewDesc(
			"xflow_sampling_rate",
			"Packet sampling rate in force for the domain, declared by its own options or inherited from the device",
			[]string{labelExporter, labelVersion, labelODID}, nil,
		),
		samplerRateDesc: prometheus.NewDesc(
			"xflow_sampler_rate",
			"Packet sampling rate a device declared for one named sampler",
			[]string{labelExporter, labelVersion, labelSampler}, nil,
		),
		declRefusedDesc: prometheus.NewDesc(
			"xflow_sampling_declarations_refused_total",
			"Sampling declarations discarded since process start, the exporter being at its sampler budget",
			nil, nil,
		),
		domainsRefusedDesc: prometheus.NewDesc(
			"xflow_domains_refused_total",
			"Datagrams refused an observation domain since process start, discarded where decoding needs one",
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
	ch <- c.lastDatagramDesc
	ch <- c.templatesDesc
	ch <- c.samplePoolDesc
	ch <- c.samplesDroppedDesc
	ch <- c.samplersRefusedDesc
	ch <- c.seqMissedDesc
	ch <- c.samplingDesc
	ch <- c.samplerRateDesc
	ch <- c.declRefusedDesc
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

		// The two instants separate a device that stopped exporting flows
		// from one that stopped sending at all.
		if snap.LastSeenUnixNano > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.lastDatagramDesc, prometheus.GaugeValue,
				float64(snap.LastSeenUnixNano)/nanosPerSecond, exporter)
		}
	}

	c.collectDomains(ch)
	c.collectSamplers(ch)

	// Seeded at zero: a first refusal must read as a rise on an existing
	// series rather than as a series appearing from nothing.
	ch <- prometheus.MustNewConstMetric(
		c.domainsRefusedDesc, prometheus.CounterValue, float64(c.src.DomainsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.declRefusedDesc, prometheus.CounterValue, float64(c.src.DeclarationsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.stringsRefusedDesc, prometheus.CounterValue, float64(c.src.VendorStringsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.appsRefusedDesc, prometheus.CounterValue, float64(c.src.ApplicationsRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.exportersRefusedDesc, prometheus.CounterValue, float64(c.src.ExportersRefused()))
	ch <- prometheus.MustNewConstMetric(
		c.samplersRefusedDesc, prometheus.CounterValue, float64(c.src.SamplersRefused()))
}

// The template kinds published in the type label.
const (
	templateKindData    = "template"
	templateKindOptions = "options_template"
)

// collectSamplers reports each device's named sampler declarations. A domain
// carrying several has no single rate in force, so these are what audit its
// correction.
func (c *DecoderCollector) collectSamplers(ch chan<- prometheus.Metric) {
	for _, sampler := range c.src.Samplers() {
		ch <- prometheus.MustNewConstMetric(
			c.samplerRateDesc, prometheus.GaugeValue, float64(sampler.Rate),
			sampler.Exporter.String(), sampler.Version.String(),
			strconv.FormatUint(uint64(sampler.Sampler), 10))
	}
}

// collectDomains reports the per-observation-domain state.
func (c *DecoderCollector) collectDomains(ch chan<- prometheus.Metric) {
	for _, domain := range c.src.Domains() {
		exporter := domain.Exporter.String()
		version := domain.Version.String()
		odid := strconv.FormatUint(uint64(domain.ODID), 10)

		// A domain publishes only what its own protocol can measure: v9 and
		// IPFIX announce templates, sFlow reports its agent's sample counters,
		// and v5 and v8 carry neither. Each sFlow counter appears once a
		// difference was taken for it.
		switch domain.Version {
		case flow.VersionNetFlowV9, flow.VersionIPFIX:
			ch <- prometheus.MustNewConstMetric(
				c.templatesDesc, prometheus.GaugeValue,
				float64(domain.Templates), exporter, version, odid, templateKindData)
			ch <- prometheus.MustNewConstMetric(
				c.templatesDesc, prometheus.GaugeValue,
				float64(domain.OptionsTemplates), exporter, version, odid, templateKindOptions)
		case flow.VersionSFlowV5:
			if domain.PoolMeasured {
				ch <- prometheus.MustNewConstMetric(
					c.samplePoolDesc, prometheus.CounterValue,
					float64(domain.SamplePool), exporter, version, odid)
			}
			if domain.DropsMeasured {
				ch <- prometheus.MustNewConstMetric(
					c.samplesDroppedDesc, prometheus.CounterValue,
					float64(domain.SamplesDropped), exporter, version, odid)
			}
		case flow.VersionNetFlowV5, flow.VersionNetFlowV8, flow.VersionUnknown:
			// Neither templates nor samplers; the sequence below is all these
			// domains are opened for.
		}

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
