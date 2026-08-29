// Package collector provides collectors for xflow-exporter.
// This file publishes the aggregation tables. Every family carries bytes,
// packets and flows; the series whose labels all read "other" carries what the
// entry bound folded at ingest, and nothing else. The tail the Top-K and
// min-bytes cuts leave below the published prefix reaches no series either: it
// is not added to other, and an entry evicted before it ever rises into the cut
// takes its totals with it.
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
	// minBytes withholds an entry below it at scrape time. Its totals reach
	// no series, other included.
	minBytes uint64

	exporters    familyDescs
	hosts        familyDescs
	services     familyDescs
	destinations familyDescs
	tcpFlags     familyDescs
	dscp         familyDescs
	asns         familyDescs
	// asnNames answers what a database calls an AS, nil where no ASN
	// database is enabled.
	asnNames     func(uint32) (string, bool)
	asnInfoDesc  *prometheus.Desc
	applications familyDescs
	countries    familyDescs
	threats      familyDescs

	entriesDesc   *prometheus.Desc
	evictionsDesc *prometheus.Desc
	overflowDesc  *prometheus.Desc
}

// NewFlowCollector creates a collector over the aggregator.
// asnNames answers what a database calls an AS. It is nil where no ASN
// database is enabled, and the naming series is then absent rather than empty.
func NewFlowCollector(
	src FlowSource, modules config.Collectors, agg config.Aggregation, asnNames func(uint32) (string, bool),
) *FlowCollector {
	c := &FlowCollector{
		src:      src,
		asnNames: asnNames,
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
		c.asnInfoDesc = prometheus.NewDesc(
			"xflow_asn_info",
			"Always 1, carrying what a database calls each AS the pair table publishes",
			[]string{labelASN, labelOrg}, nil,
		)
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
		if c.asnInfoDesc != nil {
			ch <- c.asnInfoDesc
		}
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
		cut := collectFamily(c, ch, &c.asns, c.src.ASNs, asnLabels)
		c.collectASNNames(ch, cut)
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
) []aggregator.EntrySnapshot[K] {
	entries, fold := read()

	cut := published(c, entries)
	for _, e := range cut {
		descs.emit(ch, e.Totals, labels(e.Key)...)
	}

	descs.emit(ch, fold, otherLabels(labels)...)
	return cut
}

// published sorts a table's entries and returns the ones that keep their own
// labels. Both tests fail monotonically down the sorted slice, so the cut is a
// prefix of it and anything reading the published set can take it whole.
func published[K comparable](
	c *FlowCollector, entries []aggregator.EntrySnapshot[K],
) []aggregator.EntrySnapshot[K] {
	// The largest entries by bytes keep their own series, the older entry
	// winning a tie. The order has to be total: a comparison that returns
	// zero leaves the sort free to place either first, and the snapshot
	// arrives in map order, so the cut would admit a different subset of a
	// tie group on every scrape and publish churn nothing ingested.
	slices.SortFunc(entries, func(a, b aggregator.EntrySnapshot[K]) int {
		switch {
		case a.Bytes > b.Bytes:
			return -1
		case a.Bytes < b.Bytes:
			return 1
		case a.Born < b.Born:
			return -1
		case a.Born > b.Born:
			return 1
		default:
			return 0
		}
	})

	for i, e := range entries {
		if i >= c.topK || e.Bytes < c.minBytes {
			return entries[:i]
		}
	}
	return entries
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

// collectASNNames publishes what a database calls each AS the pair table
// publishes. The name rides its own series rather than the counters': a
// database respelling a company would otherwise break every counter it
// touches. An AS no lookup resolved carries no name and so no series, which a
// join shows by finding nothing to join to.
//
// The cut arrives from the caller rather than being taken again here. The
// table moves under a scrape, so a second read answers with one the pair
// series never saw, and the cut of that read names an AS no published pair
// carries. The table below the cut runs to --aggregation.max-entries besides,
// while a database names every AS there is.
func (c *FlowCollector) collectASNNames(
	ch chan<- prometheus.Metric, cut []aggregator.EntrySnapshot[aggregator.ASNKey],
) {
	if c.asnNames == nil {
		return
	}

	// Every published pair names two AS numbers, before deduplication.
	const asnsPerPair = 2

	named := make(map[uint32]struct{}, asnsPerPair*len(cut))
	for _, e := range cut {
		for _, as := range [asnsPerPair]uint32{e.Key.SrcAS, e.Key.DstAS} {
			if as == 0 {
				continue
			}
			if _, done := named[as]; done {
				continue
			}
			named[as] = struct{}{}

			org, ok := c.asnNames(as)
			if !ok {
				continue
			}
			// A database string reaches the label unchecked: the mmdb reader
			// validates UTF-8 only in Verify. Dropping the one name Prometheus
			// cannot hold costs its own series, where the panic
			// MustNewConstMetric would raise costs every family behind it.
			m, err := prometheus.NewConstMetric(c.asnInfoDesc, prometheus.GaugeValue, 1,
				strconv.FormatUint(uint64(as), 10), org)
			if err != nil {
				continue
			}
			ch <- m
		}
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
// names; anything else renders as its number. A conventional name the registry
// assigns to a different number is not one of them: "ipip" names 4 on Linux
// and is the registry's keyword for 94, so a filter written from the registry
// would select traffic that is not what it asked for.
var protocolNames = map[uint8]string{
	1:   "icmp",
	2:   "igmp",
	4:   "ipv4",
	6:   "tcp",
	17:  "udp",
	41:  "ipv6",
	47:  "gre",
	50:  "esp",
	51:  "ah",
	58:  "icmpv6",
	88:  "eigrp",
	89:  "ospf",
	103: "pim",
	112: "vrrp",
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

// tcpFlagBits names each control bit from the low bit up, which is the order
// tcpdump prints them in and the reverse of the header's own drawing.
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
	// A segment setting no bit is a NULL scan, which the table admits, and an
	// empty label value reads as an absent label wherever it is rendered.
	if flags == 0 {
		return "none"
	}

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

// dscpNames holds every code point the IANA registry names.
//
// An unnamed point is not thereby a local convention. Only pool 2, the xxxx11
// points, is reserved for experimental or local use; elsewhere an unnamed
// point is unassigned standards space, where a name invented here would
// collide with a later registration. The unnamed traffic a campus actually
// carries is neither: 2, 4 and 5 are what a stack still marking the byte the
// way RFC 791 read it produces, and they mean maximize throughput, minimize
// delay, and both delay and reliability. Nothing on the wire separates that
// reading from a DiffServ one, so the number stands rather than a guess.
var dscpNames = map[uint8]string{
	0: "cs0", 8: "cs1", 16: "cs2", 24: "cs3",
	32: "cs4", 40: "cs5", 48: "cs6", 56: "cs7",
	10: "af11", 12: "af12", 14: "af13",
	18: "af21", 20: "af22", 22: "af23",
	26: "af31", 28: "af32", 30: "af33",
	34: "af41", 36: "af42", 38: "af43",
	1: "le", 44: "voice-admit", 45: "nqb", 46: "ef",
}

// dscpName renders the code point as the class it names, the number
// otherwise, which is the shape protocolName already uses.
func dscpName(dscp uint8) string {
	if name, ok := dscpNames[dscp]; ok {
		return name
	}
	return strconv.Itoa(int(dscp))
}
