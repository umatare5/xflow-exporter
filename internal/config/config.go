// Package config provides configuration parsing and validation.
package config

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
)

const (
	DefaultListenAddress = "0.0.0.0"
	DefaultListenPort    = 10040
	DefaultTelemetryPath = "/metrics"
	// HealthPath lives here so Validate can reject a telemetry path that takes it.
	// The server package already depends on this one, so the reverse would cycle.
	HealthPath       = "/healthz"
	DefaultLogLevel  = "info"
	DefaultLogFormat = "json"
)

// Config represents the complete configuration.
type Config struct {
	Web               Web               `json:"web"`
	Log               Log               `json:"log"`
	InternalCollector InternalCollector `json:"internal_collector"`
	DryRun            bool              `json:"dry_run"`
}

// Web holds HTTP server configuration.
type Web struct {
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
	TelemetryPath string `json:"telemetry_path"`
}

// Log holds logging configuration.
type Log struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// InternalCollector holds internal metrics collection configuration.
type InternalCollector struct {
	EnableGoCollector      bool `json:"enable_go_collector"`
	EnableProcessCollector bool `json:"enable_process_collector"`
}

// Parse parses configuration from CLI command and environment variables.
func Parse(cmd *cli.Command) (*Config, error) {
	cfg := &Config{
		Web: Web{
			ListenAddress: cmd.String("web.listen-address"),
			ListenPort:    cmd.Int("web.listen-port"),
			TelemetryPath: cmd.String("web.telemetry-path"),
		},
		Log: Log{
			Level:  cmd.String("log.level"),
			Format: cmd.String("log.format"),
		},
		InternalCollector: InternalCollector{
			EnableGoCollector:      cmd.Bool("collector.internal.go-runtime"),
			EnableProcessCollector: cmd.Bool("collector.internal.process"),
		},
		DryRun: cmd.Bool("dry-run"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// Validate performs configuration validation.
func (c *Config) Validate() error {
	validationRules := []struct {
		condition bool
		message   string
	}{
		{
			c.Web.ListenPort < 1 || c.Web.ListenPort > 65535,
			fmt.Sprintf("invalid listen port: %d (must be 1-65535)", c.Web.ListenPort),
		},
		{
			c.Web.TelemetryPath == "", "telemetry path cannot be empty",
		},
		{
			!strings.HasPrefix(c.Web.TelemetryPath, "/"),
			"telemetry path must start with '/': " + c.Web.TelemetryPath,
		},
		{
			// Whitespace and % make http.ServeMux panic at registration: it reads a
			// leading field as a method, and it unescapes a pattern before testing it
			// for conflicts, so /%68ealthz collides with the health path. A brace
			// declares a wildcard that would answer unrelated one-segment requests,
			// and ? or # never reach the server, leaving the handler unreachable.
			strings.ContainsAny(c.Web.TelemetryPath, " \t{?#%"),
			"telemetry path must not contain whitespace, '{', '?', '#' or '%': " + c.Web.TelemetryPath,
		},
		{
			// http.ServeMux redirects a request whose path needs cleaning, so metrics
			// registered at an uncleaned pattern are never served.
			path.Clean(c.Web.TelemetryPath) != c.Web.TelemetryPath,
			"telemetry path must be clean, without '.', '..' or a repeated or trailing '/': " +
				c.Web.TelemetryPath,
		},
		{
			c.Web.TelemetryPath == HealthPath,
			"telemetry path must not be " + HealthPath + ", which serves the health check",
		},
		{
			!isValidLogLevel(c.Log.Level),
			fmt.Sprintf("invalid log level: %s (must be one of: debug, info, warn, error)", c.Log.Level),
		},
		{
			!isValidLogFormat(c.Log.Format),
			fmt.Sprintf("invalid log format: %s (must be one of: json, text)", c.Log.Format),
		},
	}

	for _, rule := range validationRules {
		if rule.condition {
			return errors.New(rule.message)
		}
	}

	return nil
}

// isValidLogLevel checks if the log level is valid.
func isValidLogLevel(level string) bool {
	validLevels := []string{"debug", "info", "warn", "error"}
	return slices.Contains(validLevels, strings.ToLower(level))
}

// isValidLogFormat checks if the log format is valid.
func isValidLogFormat(format string) bool {
	validFormats := []string{"json", "text"}
	return slices.Contains(validFormats, strings.ToLower(format))
}
