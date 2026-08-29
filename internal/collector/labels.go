// Package collector provides collectors for xflow-exporter.
package collector

// Label constants used across collectors for Prometheus metrics.
const (
	labelExporter = "exporter" // Source address of the exporting device
	labelListener = "listener" // Configured receiver listen address
	labelReason   = "reason"   // Reason a counter is keyed by
	labelVersion  = "version"  // Wire protocol a datagram or record arrived in
	labelODID     = "odid"     // Observation Domain ID (v9 Source ID) within an exporter
	labelType     = "type"     // Kind a gauge is keyed by

	// Aggregation table labels.
	labelAggregation = "aggregation" // Aggregation table name
	labelSrc         = "src"         // Source address
	labelDst         = "dst"         // Destination address
	labelProto       = "proto"       // IP protocol name or number
	labelPort        = "port"        // Destination port, the service side
	labelSrcASN      = "src_asn"     // Source AS number
	labelDstASN      = "dst_asn"     // Destination AS number
	labelApplication = "application" // Resolved application name or engine:selector
)
