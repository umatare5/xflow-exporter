// Package collector provides collectors for xflow-exporter.
package collector

// Label constants used across collectors for Prometheus metrics.
const (
	labelListener = "listener" // Configured receiver listen address
	labelReason   = "reason"   // Reason a counter is keyed by
)
