// Package collector provides collectors for xflow-exporter.
// This file publishes the aggregation tables. Every family carries bytes,
// packets and flows; the series whose labels all read "other" carries what
// the entry bound folded at ingest, which is the only traffic no series of
// this family has ever published.
package collector

import (
	"slices"
	"strconv"
	"strings"

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
	Destinations() ([]aggregator.EntrySnapshot[aggregator.DestinationKey], aggregator.Totals)
	TCPFlags() ([]aggregator.EntrySnapshot[aggregator.TCPFlagsKey], aggregator.Totals)
	DSCP() ([]aggregator.EntrySnapshot[aggregator.DSCPKey], aggregator.Totals)
	ASNs() ([]aggregator.EntrySnapshot[aggregator.ASNKey], aggregator.Totals)
	Applications() ([]aggregator.EntrySnapshot[aggregator.AppKey], aggregator.Totals)
	Countries() ([]aggregator.EntrySnapshot[aggregator.CountryKey], aggregator.Totals)
	Threats() ([]aggregator.EntrySnapshot[aggregator.ThreatKey], aggregator.Totals)
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
			"Sampling-corrected bytes per "+subject+", other carries the entry-bound fold", labels, nil),
		packets: prometheus.NewDesc(prefix+"_packets_total",
			"Sampling-corrected packets per "+subject+", other carries the entry-bound fold", labels, nil),
		flows: prometheus.NewDesc(prefix+"_flows_total",
			"Flow records as exported per "+subject+", other carries the entry-bound fold", labels, nil),
	}
}

// describe sends the three descriptors.
func (f *familyDescs) describe(ch chan<- *prometheus.Desc) {
	ch <- f.bytes
	ch <- f.packets
	ch <- f.flows
}

// emit publishes one label set's totals. A label value Prometheus cannot hold
// drops that entry's three series and nothing else: the panic MustNewConstMetric
// would raise costs the scrape every family queued behind this one.
func (f *familyDescs) emit(ch chan<- prometheus.Metric, totals aggregator.Totals, labels ...string) {
	send := func(desc *prometheus.Desc, value uint64) bool {
		m, err := prometheus.NewConstMetric(desc, prometheus.CounterValue, float64(value), labels...)
		if err != nil {
			return false
		}
		ch <- m
		return true
	}

	if !send(f.bytes, totals.Bytes) {
		return
	}
	send(f.packets, totals.Packets)
	send(f.flows, totals.Flows)
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
	destinations familyDescs
	tcpFlags     familyDescs
	dscp         familyDescs
	asns         familyDescs
	applications familyDescs
	countries    familyDescs
	threats      familyDescs

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
	if modules.Destinations {
		c.destinations = newFamilyDescs("xflow_destination", "destination service",
			[]string{labelExporter, labelDst, labelProto, labelPort})
	}
	if modules.TCPFlags {
		c.tcpFlags = newFamilyDescs("xflow_tcp_flags", "TCP control-bit profile",
			[]string{labelExporter, labelFlags})
	}
	if modules.DSCP {
		c.dscp = newFamilyDescs("xflow_dscp", "DSCP class",
			[]string{labelExporter, labelDSCP})
	}
	if modules.ASNs {
		c.asns = newFamilyDescs("xflow_asn_pair", "AS pair",
			[]string{labelExporter, labelSrcASN, labelDstASN})
	}
	if modules.Applications {
		c.applications = newFamilyDescs("xflow_application", "application",
			[]string{labelExporter, labelApplication})
	}
	if modules.Countries {
		c.countries = newFamilyDescs("xflow_country_pair", "country pair",
			[]string{labelExporter, labelSrcCountry, labelDstCountry})
	}
	if modules.Threats {
		c.threats = newFamilyDescs("xflow_threat", "flagged address",
			[]string{labelExporter, labelAddress, labelDirection})
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
	if c.modules.Destinations {
		c.destinations.describe(ch)
	}
	if c.modules.TCPFlags {
		c.tcpFlags.describe(ch)
	}
	if c.modules.DSCP {
		c.dscp.describe(ch)
	}
	if c.modules.ASNs {
		c.asns.describe(ch)
	}
	if c.modules.Applications {
		c.applications.describe(ch)
	}
	if c.modules.Countries {
		c.countries.describe(ch)
	}
	if c.modules.Threats {
		c.threats.describe(ch)
	}
	ch <- c.entriesDesc
	ch <- c.evictionsDesc
	ch <- c.overflowDesc
}

// Collect implements prometheus.Collector by reading the aggregator.
//
// The health series go first. A label value the wire controls can panic the
// metric that renders it, and the recovery costs the scrape everything this
// collector had not yet emitted -- so the counters an operator would notice
// the loss by must not be queued behind the tables that can raise it.
func (c *FlowCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectHealth(ch)

	if c.modules.Exporters {
		c.collectExporters(ch)
	}
	if c.modules.Hosts {
		collectFamily(c, ch, &c.hosts, c.src.Hosts, hostLabels)
	}
	if c.modules.Services {
		collectFamily(c, ch, &c.services, c.src.Services, serviceLabels)
	}
	if c.modules.Destinations {
		collectFamily(c, ch, &c.destinations, c.src.Destinations, destinationLabels)
	}
	if c.modules.TCPFlags {
		collectFamily(c, ch, &c.tcpFlags, c.src.TCPFlags, tcpFlagsLabels)
	}
	if c.modules.DSCP {
		collectFamily(c, ch, &c.dscp, c.src.DSCP, dscpLabels)
	}
	if c.modules.ASNs {
		collectFamily(c, ch, &c.asns, c.src.ASNs, asnLabels)
	}
	if c.modules.Applications {
		collectFamily(c, ch, &c.applications, c.src.Applications, appLabels)
	}
	if c.modules.Countries {
		collectFamily(c, ch, &c.countries, c.src.Countries, countryLabels)
	}
	if c.modules.Threats {
		collectFamily(c, ch, &c.threats, c.src.Threats, threatLabels)
	}
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
// entry bound folded at ingest.
//
// The tail below the cut is not added to that series, at any point in its
// life. Its entries are still accumulating, so summing them per scrape would
// make a counter that falls whenever one of them is evicted or grows into the
// cut, which rate() reports as a reset -- and folding them once at eviction
// would double-count every entry that had been above the cut, since those
// bytes already reached Prometheus as increments on the entry's own series.
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

func destinationLabels(k aggregator.DestinationKey) []string {
	return []string{
		k.Exporter.String(), k.Dst.String(),
		protocolName(k.Protocol), strconv.Itoa(int(k.Port)),
	}
}

func tcpFlagsLabels(k aggregator.TCPFlagsKey) []string {
	return []string{k.Exporter.String(), tcpFlagNames(k.Flags)}
}

func dscpLabels(k aggregator.DSCPKey) []string {
	return []string{k.Exporter.String(), dscpName(k.DSCP)}
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

// countryLabels renders a country pair. A side the database could not place
// reads as unknown rather than as an empty label, which Prometheus cannot
// tell from a label that was never set.
func countryLabels(k aggregator.CountryKey) []string {
	return []string{k.Exporter.String(), countryLabel(k.Src), countryLabel(k.Dst)}
}

// threatLabels renders one flagged address and the side it was seen on.
func threatLabels(k aggregator.ThreatKey) []string {
	return []string{k.Exporter.String(), k.Address.String(), k.Direction}
}

// countryLabel spells one side of a pair.
func countryLabel(code string) string {
	if code == "" {
		return "unknown"
	}
	return code
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

// tcpFlagBits names each control bit in header order, which is the order
// every packet tool prints them in.
var tcpFlagBits = [8]struct {
	mask uint8
	name string
}{
	{0x01, "fin"},
	{0x02, "syn"},
	{0x04, "rst"},
	{0x08, "psh"},
	{0x10, "ack"},
	{0x20, "urg"},
	{0x40, "ece"},
	{0x80, "cwr"},
}

// tcpFlagNames renders the bits a flow ORed together.
//
// The bits are rendered rather than the byte because the byte is not what an
// operator reads: 2 and 18 are a scan and a handshake, and nothing about the
// numbers says so. Only set bits appear, so the label is short and the
// distinct values are the handful a network actually produces.
func tcpFlagNames(flags uint8) string {
	var b strings.Builder
	for _, f := range tcpFlagBits {
		if flags&f.mask == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(f.name)
	}
	return b.String()
}

// dscpNames maps the code points RFC 2474, 2597 and 3246 assign to a class.
// A point outside them is a local convention this exporter cannot name.
var dscpNames = map[uint8]string{
	0: "cs0", 8: "cs1", 16: "cs2", 24: "cs3",
	32: "cs4", 40: "cs5", 48: "cs6", 56: "cs7",
	10: "af11", 12: "af12", 14: "af13",
	18: "af21", 20: "af22", 22: "af23",
	26: "af31", 28: "af32", 30: "af33",
	34: "af41", 36: "af42", 38: "af43",
	44: "voice-admit", 46: "ef",
}

// dscpName renders the code point as the class it names, the number
// otherwise, which is the shape protocolName already uses.
func dscpName(dscp uint8) string {
	if name, ok := dscpNames[dscp]; ok {
		return name
	}
	return strconv.Itoa(int(dscp))
}
