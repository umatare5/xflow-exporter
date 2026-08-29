package config

import (
	"context"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// parseFlags mirrors the flag set internal/cli registers, so Parse can be
// driven through a real cli.Command without importing that package, which
// would cycle.
func parseFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "web.listen-address", Value: DefaultListenAddress},
		&cli.IntFlag{Name: "web.listen-port", Value: DefaultListenPort},
		&cli.StringFlag{Name: "web.telemetry-path", Value: DefaultTelemetryPath},
		&cli.StringFlag{Name: "log.level", Value: DefaultLogLevel},
		&cli.StringFlag{Name: "log.format", Value: DefaultLogFormat},
		&cli.BoolFlag{Name: "collector.internal.go-runtime"},
		&cli.BoolFlag{Name: "collector.internal.process"},
		&cli.BoolFlag{Name: "dry-run"},
	}
}

// runParse runs Parse against a real cli.Command invoked with args.
func runParse(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var cfg *Config
	var parseErr error

	cmd := &cli.Command{
		Name:  "xflow-exporter-test",
		Flags: parseFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			cfg, parseErr = Parse(cmd)
			return nil
		},
	}

	if err := cmd.Run(context.Background(), append([]string{"xflow-exporter-test"}, args...)); err != nil {
		t.Fatalf("cli.Command.Run() error = %v, want nil", err)
	}
	return cfg, parseErr
}

func TestParse_Defaults(t *testing.T) {
	t.Parallel()

	cfg, err := runParse(t)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	if cfg.Web.ListenAddress != DefaultListenAddress {
		t.Errorf("ListenAddress = %q, want %q", cfg.Web.ListenAddress, DefaultListenAddress)
	}
	if cfg.Web.ListenPort != DefaultListenPort {
		t.Errorf("ListenPort = %d, want %d", cfg.Web.ListenPort, DefaultListenPort)
	}
	if cfg.Web.TelemetryPath != DefaultTelemetryPath {
		t.Errorf("TelemetryPath = %q, want %q", cfg.Web.TelemetryPath, DefaultTelemetryPath)
	}
	if cfg.Log.Level != DefaultLogLevel {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, DefaultLogLevel)
	}
	if cfg.Log.Format != DefaultLogFormat {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, DefaultLogFormat)
	}
	if cfg.InternalCollector.EnableGoCollector {
		t.Error("EnableGoCollector = true, want false")
	}
	if cfg.InternalCollector.EnableProcessCollector {
		t.Error("EnableProcessCollector = true, want false")
	}
	if cfg.DryRun {
		t.Error("DryRun = true, want false")
	}
}

func TestParse_Overrides(t *testing.T) {
	t.Parallel()

	cfg, err := runParse(t,
		"--web.listen-address", "127.0.0.1",
		"--web.listen-port", "19999",
		"--web.telemetry-path", "/xflow-metrics",
		"--log.level", "debug",
		"--log.format", "text",
		"--collector.internal.go-runtime",
		"--collector.internal.process",
		"--dry-run",
	)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	if cfg.Web.ListenAddress != "127.0.0.1" {
		t.Errorf("ListenAddress = %q, want 127.0.0.1", cfg.Web.ListenAddress)
	}
	if cfg.Web.ListenPort != 19999 {
		t.Errorf("ListenPort = %d, want 19999", cfg.Web.ListenPort)
	}
	if cfg.Web.TelemetryPath != "/xflow-metrics" {
		t.Errorf("TelemetryPath = %q, want /xflow-metrics", cfg.Web.TelemetryPath)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %q, want text", cfg.Log.Format)
	}
	if !cfg.InternalCollector.EnableGoCollector {
		t.Error("EnableGoCollector = false, want true")
	}
	if !cfg.InternalCollector.EnableProcessCollector {
		t.Error("EnableProcessCollector = false, want true")
	}
	if !cfg.DryRun {
		t.Error("DryRun = false, want true")
	}
}

func TestParse_InvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, err := runParse(t, "--web.listen-port", "0")
	if err == nil {
		t.Fatal("Parse() error = nil, want a validation error")
	}
	if !strings.Contains(err.Error(), "configuration validation failed") {
		t.Errorf("Parse() error = %v, want it to wrap the validation failure", err)
	}
}

// validConfig returns a configuration every Validate rule accepts.
func validConfig() *Config {
	return &Config{
		Web: Web{
			ListenAddress: DefaultListenAddress,
			ListenPort:    DefaultListenPort,
			TelemetryPath: DefaultTelemetryPath,
		},
		Log: Log{
			Level:  DefaultLogLevel,
			Format: DefaultLogFormat,
		},
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "valid defaults",
			mutate:  func(*Config) {},
			wantErr: "",
		},
		{
			name:    "port below range",
			mutate:  func(c *Config) { c.Web.ListenPort = 0 },
			wantErr: "invalid listen port",
		},
		{
			name:    "port above range",
			mutate:  func(c *Config) { c.Web.ListenPort = 65536 },
			wantErr: "invalid listen port",
		},
		{
			name:    "empty telemetry path",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "" },
			wantErr: "telemetry path cannot be empty",
		},
		{
			name:    "telemetry path without leading slash",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "metrics" },
			wantErr: "must start with '/'",
		},
		{
			name:    "telemetry path with whitespace",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/met rics" },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "telemetry path with tab",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/met\trics" },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "telemetry path with brace wildcard",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/{metrics}" },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "telemetry path with query separator",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/metrics?x=1" },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "telemetry path with fragment",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/metrics#top" },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "telemetry path with percent escape",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/%68ealthz" },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "telemetry path with dot segment",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/metrics/../metrics" },
			wantErr: "must be clean",
		},
		{
			name:    "telemetry path with trailing slash",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/metrics/" },
			wantErr: "must be clean",
		},
		{
			name:    "telemetry path with repeated slash",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "//metrics" },
			wantErr: "must be clean",
		},
		{
			name:    "telemetry path taking the health path",
			mutate:  func(c *Config) { c.Web.TelemetryPath = HealthPath },
			wantErr: "which serves the health check",
		},
		{
			name:    "telemetry path at the root is allowed",
			mutate:  func(c *Config) { c.Web.TelemetryPath = "/" },
			wantErr: "",
		},
		{
			name:    "invalid log level",
			mutate:  func(c *Config) { c.Log.Level = "verbose" },
			wantErr: "invalid log level",
		},
		{
			name:    "upper case log level is accepted",
			mutate:  func(c *Config) { c.Log.Level = "DEBUG" },
			wantErr: "",
		},
		{
			name:    "invalid log format",
			mutate:  func(c *Config) { c.Log.Format = "logfmt" },
			wantErr: "invalid log format",
		},
		{
			name:    "upper case log format is accepted",
			mutate:  func(c *Config) { c.Log.Format = "JSON" },
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			tt.mutate(cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level string
		want  bool
	}{
		{"debug", true},
		{"info", true},
		{"warn", true},
		{"error", true},
		{"WARN", true},
		{"warning", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run("level "+tt.level, func(t *testing.T) {
			t.Parallel()

			if got := isValidLogLevel(tt.level); got != tt.want {
				t.Errorf("isValidLogLevel(%q) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

func TestIsValidLogFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format string
		want   bool
	}{
		{"json", true},
		{"text", true},
		{"TEXT", true},
		{"logfmt", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run("format "+tt.format, func(t *testing.T) {
			t.Parallel()

			if got := isValidLogFormat(tt.format); got != tt.want {
				t.Errorf("isValidLogFormat(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}
