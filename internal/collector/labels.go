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
)
