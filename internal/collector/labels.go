// This file holds the label names the aggregation and self-monitoring
// collectors share, so two families cannot drift apart on a spelling.

package collector

const (
	labelExporter = "exporter_address" // Source address of the exporting device
	labelListener = "listener"         // Configured receiver listen address
	labelReason   = "reason"           // Reason a counter is keyed by
	labelVersion  = "version"          // Wire protocol a datagram or record arrived in
	labelODID     = "odid"             // Observation Domain ID (v9 Source ID) within an exporter
	labelType     = "type"             // Kind a gauge is keyed by

	// Aggregation table labels.
	labelAggregation = "aggregation"    // Aggregation table name
	labelSrc         = "src"            // Source address
	labelDst         = "dst"            // Destination address
	labelProto       = "proto"          // IP protocol name or number
	labelPort        = "port"           // Destination port, the service side
	labelFlags       = "flags"          // TCP control bits a flow ORed together
	labelDSCP        = "dscp"           // Differentiated-services code point name or number
	labelSrcASN      = "src_asn"        // Source AS number
	labelDstASN      = "dst_asn"        // Destination AS number
	labelASN         = "asn"            // One AS number, on the series naming it
	labelOrg         = "organization"   // What a database calls that AS
	labelApplication = "application"    // Resolved application name or engine:selector
	labelAddress     = "address"        // A single address a series is keyed by
	labelDirection   = "direction"      // Side of the flow an address was seen on
	labelSrcCountry  = "src_country"    // ISO country code of the source address
	labelDstCountry  = "dst_country"    // ISO country code of the destination address
	labelInputIf     = "input_ifindex"  // ifIndex the flow entered the device on
	labelOutputIf    = "output_ifindex" // ifIndex the flow left the device on

	// Naming labels, on the info series that carry the mapping file's strings.
	labelExporterName = "exporter_name" // What the file calls that device
	labelIfIndex      = "ifindex"       // One ifIndex, on the series naming it
	labelIfName       = "ifname"        // What the file calls that interface

	// Enrichment labels.
	labelEnricher = "enricher" // Enrichment source a lookup went through
	labelResult   = "result"   // What an enrichment source made of a record
)
