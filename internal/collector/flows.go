// Package collector provides collectors for xflow-exporter.
// This file publishes the aggregation tables. Every family carries bytes,
// packets and flows; the entries past the Top-K bound or under the byte
// threshold fold into one series whose labels all read "other", alongside
// what the entry bound already folded at ingest.
package collector

import (
	"slices"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
)

// otherLabel is the label value of the fold bucket.
const otherLabel = "other"

// FlowSource is what this collector reads from the aggregator.
type FlowSource interface {
	Exporters() ([]aggregator.EntrySnapshot[aggregator.ExporterKey], aggregator.Totals)
	Hosts() ([]aggregator.EntrySnapshot[aggregator.HostKey], aggregator.Totals)
	Services() ([]aggregator.EntrySnapshot[aggregator.ServiceKey], aggregator.Totals)
	ASNs() ([]aggregator.EntrySnapshot[aggregator.ASNKey], aggregator.Totals)
	Applications() ([]aggregator.EntrySnapshot[aggregator.AppKey], aggregator.Totals)
	Health() []aggregator.TableHealth
}

// familyDescs is one aggregation's three descriptors.
type familyDescs struct {
	bytes   *prometheus.Desc
	packets *prometheus.Desc
	flows   *prometheus.Desc
}

// newFamilyDescs builds the three descriptors of one family.
func newFamilyDescs(prefix, subject string, labels []string) familyDescs {
	return familyDescs{
		bytes: prometheus.NewDesc(prefix+"_bytes_total",
			"Sampling-corrected bytes per "+subject+", other folds the rest", labels, nil),
		packets: prometheus.NewDesc(prefix+"_packets_total",
			"Sampling-corrected packets per "+subject+", other folds the rest", labels, nil),
		flows: prometheus.NewDesc(prefix+"_flows_total",
			"Flow records as exported per "+subject+", other folds the rest", labels, nil),
	}
}

// describe sends the three descriptors.
func (f *familyDescs) describe(ch chan<- *prometheus.Desc) {
	ch <- f.bytes
	ch <- f.packets
	ch <- f.flows
}

// emit publishes one label set's totals.
func (f *familyDescs) emit(ch chan<- prometheus.Metric, totals aggregator.Totals, labels ...string) {
	ch <- prometheus.MustNewConstMetric(f.bytes, prometheus.CounterValue, float64(totals.Bytes), labels...)
	ch <- prometheus.MustNewConstMetric(f.packets, prometheus.CounterValue, float64(totals.Packets), labels...)
	ch <- prometheus.MustNewConstMetric(f.flows, prometheus.CounterValue, float64(totals.Flows), labels...)
}

// FlowCollector publishes the enabled aggregation tables.
type FlowCollector struct {
	src     FlowSource
	modules config.Collectors
	topK    int
	// minBytes folds an entry below it into other at scrape time.
	minBytes uint64

	exporters    familyDescs
	hosts        familyDescs
	services     familyDescs
	asns         familyDescs
	applications familyDescs

	entriesDesc   *prometheus.Desc
	evictionsDesc *prometheus.Desc
	overflowDesc  *prometheus.Desc
}

// NewFlowCollector creates a collector over the aggregator.
func NewFlowCollector(src FlowSource, modules config.Collectors, agg config.Aggregation) *FlowCollector {
	c := &FlowCollector{
		src:      src,
		modules:  modules,
		topK:     agg.TopK,
		minBytes: uint64(agg.MinBytes), //nolint:gosec // Validate rejects negatives.
		entriesDesc: prometheus.NewDesc(
			"xflow_aggregation_entries",
			"Entries held per aggregation table",
			[]string{labelAggregation}, nil,
		),
		evictionsDesc: prometheus.NewDesc(
			"xflow_aggregation_evictions_total",
			"Idle entries evicted per aggregation table since process start",
			[]string{labelAggregation}, nil,
		),
		overflowDesc: prometheus.NewDesc(
			"xflow_aggregation_overflow_records_total",
			"Records folded into other by the entry bound since process start",
			[]string{labelAggregation}, nil,
		),
	}

	if modules.Exporters {
		c.exporters = newFamilyDescs("xflow_exporter", "exporter and version",
			[]string{labelExporter, labelVersion})
	}
	if modules.Hosts {
		c.hosts = newFamilyDescs("xflow_host_pair", "source-destination pair",
			[]string{labelExporter, labelSrc, labelDst})
	}
	if modules.Services {
		c.services = newFamilyDescs("xflow_service", "service five-tuple",
			[]string{labelExporter, labelSrc, labelDst, labelProto, labelPort})
	}
	if modules.ASNs {
		c.asns = newFamilyDescs("xflow_asn_pair", "AS pair",
			[]string{labelExporter, labelSrcASN, labelDstASN})
	}
	if modules.Applications {
		c.applications = newFamilyDescs("xflow_application", "application",
			[]string{labelExporter, labelApplication})
	}

	return c
}

// Describe implements prometheus.Collector.
func (c *FlowCollector) Describe(ch chan<- *prometheus.Desc) {
	if c.modules.Exporters {
		c.exporters.describe(ch)
	}
	if c.modules.Hosts {
		c.hosts.describe(ch)
	}
	if c.modules.Services {
		c.services.describe(ch)
	}
	if c.modules.ASNs {
		c.asns.describe(ch)
	}
	if c.modules.Applications {
		c.applications.describe(ch)
	}
	ch <- c.entriesDesc
	ch <- c.evictionsDesc
	ch <- c.overflowDesc
}

// Collect implements prometheus.Collector by reading the aggregator.
func (c *FlowCollector) Collect(ch chan<- prometheus.Metric) {
	if c.modules.Exporters {
		c.collectExporters(ch)
	}
	if c.modules.Hosts {
		collectFamily(c, ch, &c.hosts, c.src.Hosts, hostLabels)
	}
	if c.modules.Services {
		collectFamily(c, ch, &c.services, c.src.Services, serviceLabels)
	}
	if c.modules.ASNs {
		collectFamily(c, ch, &c.asns, c.src.ASNs, asnLabels)
	}
	if c.modules.Applications {
		collectFamily(c, ch, &c.applications, c.src.Applications, appLabels)
	}

	c.collectHealth(ch)
}

// collectExporters publishes the per-device table without folding: its
// cardinality is the fleet's, which no Top-K needs to guard.
func (c *FlowCollector) collectExporters(ch chan<- prometheus.Metric) {
	entries, overflow := c.src.Exporters()
	for _, e := range entries {
		c.exporters.emit(ch, e.Totals, e.Key.Exporter.String(), e.Key.Version.String())
	}
	c.exporters.emit(ch, overflow, otherLabel, otherLabel)
}

// collectFamily publishes one folded table: the Top-K entries at or above the
// byte threshold keep their labels, and the other series carries what the
// table folded at ingest or at eviction.
//
// The live tail below the cut is not added to that series. Its entries are
// still accumulating, so summing them per scrape would make a counter that
// falls whenever one of them is evicted or grows into the cut, which rate()
// reports as a reset. A tail entry reaches the other series when it is
// evicted, and until then it is simply not published.
func collectFamily[K comparable](
	c *FlowCollector, ch chan<- prometheus.Metric, descs *familyDescs,
	read func() ([]aggregator.EntrySnapshot[K], aggregator.Totals),
	labels func(K) []string,
) {
	entries, fold := read()

	// The largest entries by bytes keep their own series.
	slices.SortFunc(entries, func(a, b aggregator.EntrySnapshot[K]) int {
		switch {
		case a.Bytes > b.Bytes:
			return -1
		case a.Bytes < b.Bytes:
			return 1
		default:
			return 0
		}
	})

	for i, e := range entries {
		if i < c.topK && e.Bytes >= c.minBytes {
			descs.emit(ch, e.Totals, labels(e.Key)...)
		}
	}

	descs.emit(ch, fold, otherLabels(labels)...)
}

// otherLabels builds the all-other label set of one family, sized by probing
// the label function with a zero key.
func otherLabels[K comparable](labels func(K) []string) []string {
	var zero K
	values := make([]string, len(labels(zero)))
	for i := range values {
		values[i] = otherLabel
	}
	return values
}

// collectHealth publishes the table sizes and eviction counters.
func (c *FlowCollector) collectHealth(ch chan<- prometheus.Metric) {
	for _, h := range c.src.Health() {
		ch <- prometheus.MustNewConstMetric(
			c.entriesDesc, prometheus.GaugeValue, float64(h.Entries), h.Aggregation)
		ch <- prometheus.MustNewConstMetric(
			c.evictionsDesc, prometheus.CounterValue, float64(h.IdleEvictions), h.Aggregation)
		ch <- prometheus.MustNewConstMetric(
			c.overflowDesc, prometheus.CounterValue, float64(h.CapacityFolds), h.Aggregation)
	}
}

// Label builders per family.

func hostLabels(k aggregator.HostKey) []string {
	return []string{k.Exporter.String(), k.Src.String(), k.Dst.String()}
}

func serviceLabels(k aggregator.ServiceKey) []string {
	return []string{
		k.Exporter.String(), k.Src.String(), k.Dst.String(),
		protocolName(k.Protocol), strconv.Itoa(int(k.Port)),
	}
}

func asnLabels(k aggregator.ASNKey) []string {
	return []string{
		k.Exporter.String(),
		strconv.FormatUint(uint64(k.SrcAS), 10),
		strconv.FormatUint(uint64(k.DstAS), 10),
	}
}

func appLabels(k aggregator.AppKey) []string {
	return []string{k.Exporter.String(), k.Name}
}

// protocolNames maps the common IANA protocol numbers to their conventional
// names; anything else renders as its number.
var protocolNames = map[uint8]string{
	1:   "icmp",
	6:   "tcp",
	17:  "udp",
	47:  "gre",
	50:  "esp",
	51:  "ah",
	58:  "icmpv6",
	89:  "ospf",
	132: "sctp",
}

// protocolName renders an IP protocol number as its conventional name, and
// the number itself for one outside the map.
func protocolName(protocol uint8) string {
	if name, ok := protocolNames[protocol]; ok {
		return name
	}
	return strconv.Itoa(int(protocol))
}
