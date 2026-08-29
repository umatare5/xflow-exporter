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
		&cli.StringSliceFlag{Name: "receiver.address", Value: []string{DefaultReceiverAddress}},
		&cli.IntFlag{Name: "receiver.batch-size", Value: DefaultReceiverBatchSize},
		&cli.IntFlag{Name: "receiver.queue-size", Value: DefaultReceiverQueueSize},
		&cli.IntFlag{Name: "receiver.buffer-bytes", Value: DefaultReceiverSockBufBytes},
		&cli.IntFlag{Name: "receiver.max-packet-size", Value: DefaultReceiverMaxPacketSize},
		&cli.IntFlag{Name: "receiver.workers", Value: DefaultReceiverWorkers},
		&cli.IntFlag{Name: "parser.max-fields-per-template", Value: DefaultParserMaxFieldsPerTemplate},
		&cli.DurationFlag{Name: "parser.template-ttl", Value: DefaultParserTemplateTTL},
		&cli.DurationFlag{Name: "aggregation.entry-ttl", Value: DefaultAggregationEntryTTL},
		&cli.IntFlag{Name: "aggregation.max-entries", Value: DefaultAggregationMaxEntries},
		&cli.IntFlag{Name: "aggregation.top-k", Value: DefaultAggregationTopK},
		&cli.Int64Flag{Name: "aggregation.min-bytes", Value: DefaultAggregationMinBytes},
		&cli.StringFlag{Name: "log.level", Value: DefaultLogLevel},
		&cli.StringFlag{Name: "log.format", Value: DefaultLogFormat},
		&cli.BoolFlag{Name: "collector.internal.go-runtime"},
		&cli.BoolFlag{Name: "collector.internal.process"},
		&cli.BoolFlag{Name: "enrich.services"},
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
	if len(cfg.Receiver.Addresses) != 1 || cfg.Receiver.Addresses[0] != DefaultReceiverAddress {
		t.Errorf("Receiver.Addresses = %v, want [%s]", cfg.Receiver.Addresses, DefaultReceiverAddress)
	}
	if cfg.Receiver.BatchSize != DefaultReceiverBatchSize {
		t.Errorf("Receiver.BatchSize = %d, want %d", cfg.Receiver.BatchSize, DefaultReceiverBatchSize)
	}
	if cfg.Receiver.QueueSize != DefaultReceiverQueueSize {
		t.Errorf("Receiver.QueueSize = %d, want %d", cfg.Receiver.QueueSize, DefaultReceiverQueueSize)
	}
	if cfg.Receiver.SockBufBytes != DefaultReceiverSockBufBytes {
		t.Errorf("Receiver.SockBufBytes = %d, want %d", cfg.Receiver.SockBufBytes, DefaultReceiverSockBufBytes)
	}
	if cfg.Receiver.MaxPacketSize != DefaultReceiverMaxPacketSize {
		t.Errorf("Receiver.MaxPacketSize = %d, want %d", cfg.Receiver.MaxPacketSize, DefaultReceiverMaxPacketSize)
	}
	if cfg.Receiver.Workers != DefaultReceiverWorkers {
		t.Errorf("Receiver.Workers = %d, want %d", cfg.Receiver.Workers, DefaultReceiverWorkers)
	}
	if cfg.Parser.MaxFieldsPerTemplate != DefaultParserMaxFieldsPerTemplate {
		t.Errorf("Parser.MaxFieldsPerTemplate = %d, want %d",
			cfg.Parser.MaxFieldsPerTemplate, DefaultParserMaxFieldsPerTemplate)
	}
	if cfg.Parser.TemplateTTL != DefaultParserTemplateTTL {
		t.Errorf("Parser.TemplateTTL = %v, want %v", cfg.Parser.TemplateTTL, DefaultParserTemplateTTL)
	}
	if cfg.Aggregation.EntryTTL != DefaultAggregationEntryTTL {
		t.Errorf("Aggregation.EntryTTL = %v, want %v", cfg.Aggregation.EntryTTL, DefaultAggregationEntryTTL)
	}
	if cfg.Aggregation.MaxEntries != DefaultAggregationMaxEntries {
		t.Errorf("Aggregation.MaxEntries = %d, want %d", cfg.Aggregation.MaxEntries, DefaultAggregationMaxEntries)
	}
	if cfg.Aggregation.TopK != DefaultAggregationTopK {
		t.Errorf("Aggregation.TopK = %d, want %d", cfg.Aggregation.TopK, DefaultAggregationTopK)
	}
	if cfg.Aggregation.MinBytes != DefaultAggregationMinBytes {
		t.Errorf("Aggregation.MinBytes = %d, want %d", cfg.Aggregation.MinBytes, DefaultAggregationMinBytes)
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
		"--receiver.address", "127.0.0.1:2055",
		"--receiver.address", "[::1]:6343",
		"--receiver.batch-size", "8",
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
	if len(cfg.Receiver.Addresses) != 2 ||
		cfg.Receiver.Addresses[0] != "127.0.0.1:2055" || cfg.Receiver.Addresses[1] != "[::1]:6343" {
		t.Errorf("Receiver.Addresses = %v, want the two configured listeners", cfg.Receiver.Addresses)
	}
	if cfg.Receiver.BatchSize != 8 {
		t.Errorf("Receiver.BatchSize = %d, want 8", cfg.Receiver.BatchSize)
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
		Receiver: Receiver{
			Addresses:     []string{DefaultReceiverAddress},
			BatchSize:     DefaultReceiverBatchSize,
			QueueSize:     DefaultReceiverQueueSize,
			SockBufBytes:  DefaultReceiverSockBufBytes,
			MaxPacketSize: DefaultReceiverMaxPacketSize,
		},
		Parser: Parser{
			MaxFieldsPerTemplate: DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          DefaultParserTemplateTTL,
		},
		Aggregation: Aggregation{
			EntryTTL:   DefaultAggregationEntryTTL,
			MaxEntries: DefaultAggregationMaxEntries,
			TopK:       DefaultAggregationTopK,
			MinBytes:   DefaultAggregationMinBytes,
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
			name:    "no receiver address",
			mutate:  func(c *Config) { c.Receiver.Addresses = nil },
			wantErr: "at least one receiver address",
		},
		{
			name:    "receiver address without a port",
			mutate:  func(c *Config) { c.Receiver.Addresses = []string{"127.0.0.1"} },
			wantErr: "invalid receiver address",
		},
		{
			name:    "receiver address with port zero",
			mutate:  func(c *Config) { c.Receiver.Addresses = []string{":0"} },
			wantErr: "port must be 1-65535",
		},
		{
			name:    "receiver address with a hostname",
			mutate:  func(c *Config) { c.Receiver.Addresses = []string{"localhost:2055"} },
			wantErr: "host must be an IP address or empty",
		},
		{
			name:    "duplicate receiver address",
			mutate:  func(c *Config) { c.Receiver.Addresses = []string{":2055", ":2055"} },
			wantErr: "duplicate receiver address",
		},
		{
			name:    "receiver IPv6 address is accepted",
			mutate:  func(c *Config) { c.Receiver.Addresses = []string{"[::1]:6343"} },
			wantErr: "",
		},
		{
			name:    "receiver batch size zero",
			mutate:  func(c *Config) { c.Receiver.BatchSize = 0 },
			wantErr: "invalid receiver batch size",
		},
		{
			name:    "receiver batch size above bound",
			mutate:  func(c *Config) { c.Receiver.BatchSize = 1025 },
			wantErr: "invalid receiver batch size",
		},
		{
			name:    "receiver queue size zero",
			mutate:  func(c *Config) { c.Receiver.QueueSize = 0 },
			wantErr: "invalid receiver queue size",
		},
		{
			name:    "receiver negative buffer bytes",
			mutate:  func(c *Config) { c.Receiver.SockBufBytes = -1 },
			wantErr: "invalid receiver buffer bytes",
		},
		{
			name:    "receiver buffer bytes zero keeps the OS default",
			mutate:  func(c *Config) { c.Receiver.SockBufBytes = 0 },
			wantErr: "",
		},
		{
			name:    "receiver max packet size below minimum",
			mutate:  func(c *Config) { c.Receiver.MaxPacketSize = 100 },
			wantErr: "invalid receiver max packet size",
		},
		{
			name:    "receiver max packet size above maximum",
			mutate:  func(c *Config) { c.Receiver.MaxPacketSize = 70000 },
			wantErr: "invalid receiver max packet size",
		},
		{
			name:    "receiver negative workers",
			mutate:  func(c *Config) { c.Receiver.Workers = -1 },
			wantErr: "invalid receiver workers",
		},
		{
			name:    "receiver workers above bound",
			mutate:  func(c *Config) { c.Receiver.Workers = 257 },
			wantErr: "invalid receiver workers",
		},
		{
			name:    "parser max fields zero",
			mutate:  func(c *Config) { c.Parser.MaxFieldsPerTemplate = 0 },
			wantErr: "invalid parser max fields per template",
		},
		{
			name:    "parser max fields above the flowset bound",
			mutate:  func(c *Config) { c.Parser.MaxFieldsPerTemplate = 16384 },
			wantErr: "invalid parser max fields per template",
		},
		{
			name:    "parser template TTL zero",
			mutate:  func(c *Config) { c.Parser.TemplateTTL = 0 },
			wantErr: "parser template TTL must be positive",
		},
		{
			name:    "aggregation entry TTL zero",
			mutate:  func(c *Config) { c.Aggregation.EntryTTL = 0 },
			wantErr: "aggregation entry TTL must be positive",
		},
		{
			name:    "aggregation max entries zero",
			mutate:  func(c *Config) { c.Aggregation.MaxEntries = 0 },
			wantErr: "invalid aggregation max entries",
		},
		{
			name:    "aggregation top-k zero",
			mutate:  func(c *Config) { c.Aggregation.TopK = 0 },
			wantErr: "invalid aggregation top-k",
		},
		{
			name:    "aggregation negative min bytes",
			mutate:  func(c *Config) { c.Aggregation.MinBytes = -1 },
			wantErr: "invalid aggregation min bytes",
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
