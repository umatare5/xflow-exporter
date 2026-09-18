package collector

import (
	"github.com/umatare5/xflow-exporter/internal/aggregator"
)

// aggregationNames is every aggregation label value, in the order Collect
// walks the tables. It is the vocabulary the entry listing answers to, and a
// test pins it against the aggregator's own table names.
var aggregationNames = []string{
	"exporters", "hosts", "services", "destinations", "tcp_flags", "dscp",
	"asns", "applications", "countries", "threats", "vlans",
}

// EntryTotals is one bucket's counters as the listing reports them.
type EntryTotals struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// EntryRow is one entry. Labels carries the values LabelNames names, in that
// order rather than as a map of its own: a table runs to
// --aggregation.max-entries, and a map per row costs five times the allocation
// to say the same thing.
type EntryRow struct {
	Rank   int      `json:"rank"`
	Labels []string `json:"labels"`
	EntryTotals
}

// AggregationEntries is one table as the listing reports it. Rank follows the
// scrape's own order, so a row at or below Published is one /metrics carries
// and the rest are what the cuts withheld.
type AggregationEntries struct {
	Entries        int         `json:"entries"`
	Published      int         `json:"published"`
	Withheld       int         `json:"withheld"`
	WithheldTotals EntryTotals `json:"withheld_totals"`
	// Other is the entry-bound fold, which is the other series on /metrics.
	// The withheld tail is no part of it, for the reason collectFamily gives.
	Other      EntryTotals `json:"other"`
	LabelNames []string    `json:"label_names"`
	Rows       []EntryRow  `json:"rows"`
}

// Aggregations names every table a listing may ask for, enabled or not.
func (c *FlowCollector) Aggregations() []string {
	return aggregationNames
}

// EntryScope reports the cuts the listing read the tables under.
func (c *FlowCollector) EntryScope() (topK int, minBytes uint64) {
	return c.topK, c.minBytes
}

// Entries reads one table under the sort and cut a scrape uses, so a row's
// rank against Published answers whether /metrics carries that entry.
//
// A disabled table reports false rather than an empty report: no series of
// its exists either, and absence is how this exporter spells that.
func (c *FlowCollector) Entries(name string) (AggregationEntries, bool) {
	switch name {
	case "exporters":
		return exporterEntries(c)
	case "hosts":
		return entriesOf(c, c.modules.Hosts, &c.hosts, c.src.Hosts, hostLabels)
	case "services":
		return entriesOf(c, c.modules.Services, &c.services, c.src.Services, serviceLabels)
	case "destinations":
		return entriesOf(c, c.modules.Destinations, &c.destinations, c.src.Destinations, destinationLabels)
	case "tcp_flags":
		return entriesOf(c, c.modules.TCPFlags, &c.tcpFlags, c.src.TCPFlags, tcpFlagsLabels)
	case "dscp":
		return entriesOf(c, c.modules.DSCP, &c.dscp, c.src.DSCP, dscpLabels)
	case "asns":
		return entriesOf(c, c.modules.ASNs, &c.asns, c.src.ASNs, asnLabels)
	case "applications":
		return entriesOf(c, c.modules.Applications, &c.applications, c.src.Applications, appLabels)
	case "countries":
		return entriesOf(c, c.modules.Countries, &c.countries, c.src.Countries, countryLabels)
	case "threats":
		return entriesOf(c, c.modules.Threats, &c.threats, c.src.Threats, threatLabels)
	case "vlans":
		return entriesOf(c, c.modules.VLANs, &c.vlans, c.src.VLANs, vlanLabels)
	}
	return AggregationEntries{}, false
}

// entriesOf reads one table and cuts it as collectFamily does.
func entriesOf[K comparable](
	c *FlowCollector, enabled bool, descs *familyDescs,
	read func() ([]aggregator.EntrySnapshot[K], aggregator.Totals),
	labels func(K) []string,
) (AggregationEntries, bool) {
	if !enabled {
		return AggregationEntries{}, false
	}

	entries, fold := read()
	return report(descs, entries, published(c, entries), fold, labels), true
}

// exporterEntries reads the per-device table, which collectExporters publishes
// whole. Sorting it ranks the rows; cutting it would report a withheld set
// that /metrics does not have.
func exporterEntries(c *FlowCollector) (AggregationEntries, bool) {
	if !c.modules.Exporters {
		return AggregationEntries{}, false
	}

	entries, fold := c.src.Exporters()
	sortEntries(entries)
	return report(&c.exporters, entries, entries, fold, exporterLabels), true
}

// report builds one table's listing from its sorted entries and the prefix the
// cut kept.
func report[K comparable](
	descs *familyDescs, entries, cut []aggregator.EntrySnapshot[K],
	fold aggregator.Totals, labels func(K) []string,
) AggregationEntries {
	rows := make([]EntryRow, 0, len(entries))
	var withheld EntryTotals

	for i, e := range entries {
		rows = append(rows, EntryRow{Rank: i + 1, Labels: labels(e.Key), EntryTotals: totalsOf(e.Totals)})
		if i < len(cut) {
			continue
		}
		withheld.Bytes += e.Bytes
		withheld.Packets += e.Packets
		withheld.Flows += e.Flows
	}

	return AggregationEntries{
		Entries:        len(entries),
		Published:      len(cut),
		Withheld:       len(entries) - len(cut),
		WithheldTotals: withheld,
		Other:          totalsOf(fold),
		LabelNames:     descs.labels,
		Rows:           rows,
	}
}

func totalsOf(t aggregator.Totals) EntryTotals {
	return EntryTotals{Bytes: t.Bytes, Packets: t.Packets, Flows: t.Flows}
}
