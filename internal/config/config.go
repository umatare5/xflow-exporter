// Package config provides configuration parsing and validation.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
)

const (
	DefaultListenAddress = "0.0.0.0"
	DefaultListenPort    = 10052
	DefaultTelemetryPath = "/metrics"

	// DefaultReceiverAddress is where flow datagrams are expected. 2055 is the
	// port NetFlow and IPFIX exporters are conventionally pointed at, and every
	// listener accepts every supported protocol, so an sFlow deployment adds
	// its own address rather than changing this one.
	DefaultReceiverAddress = ":2055"
	// DefaultReceiverBatchSize bounds how many datagrams one kernel round trip
	// may hand back on platforms with recvmmsg.
	DefaultReceiverBatchSize = 64
	// DefaultReceiverQueueSize bounds the datagrams held between the read loops
	// and the decoders, which is what absorbs an export burst.
	DefaultReceiverQueueSize = 8192
	// DefaultReceiverSockBufBytes is the SO_RCVBUF asked of the kernel. Linux
	// clamps it to net.core.rmem_max, which this exporter cannot raise.
	DefaultReceiverSockBufBytes = 4 * 1024 * 1024
	// DefaultReceiverMaxPacketSize is the largest datagram kept whole. It
	// covers a jumbo frame; a larger datagram is counted and dropped rather
	// than decoded from a truncated buffer.
	DefaultReceiverMaxPacketSize = 9216
	// DefaultReceiverWorkers of zero sizes the decode worker pool to
	// GOMAXPROCS at startup.
	DefaultReceiverWorkers = 0

	// DefaultParserMaxFieldsPerTemplate bounds a NetFlow v9 or IPFIX template
	// against memory exhaustion by a template defining tens of thousands of
	// tiny fields.
	DefaultParserMaxFieldsPerTemplate = 128
	// DefaultParserTemplateTTL is how long an unrefreshed template stays
	// usable. Devices resend templates every few minutes, so half an hour of
	// silence means the template is orphaned.
	DefaultParserTemplateTTL = 30 * time.Minute

	// DefaultAggregationEntryTTL is how long an idle aggregation entry stays
	// before eviction removes it, and its series with it.
	DefaultAggregationEntryTTL = 15 * time.Minute
	// DefaultAggregationMaxEntries bounds each aggregation table; a record
	// past the bound folds into the table's other bucket.
	DefaultAggregationMaxEntries = 100000
	// DefaultAggregationTopK bounds how many entries each table publishes as
	// their own series; the rest fold into the other bucket at scrape time.
	DefaultAggregationTopK = 1000
	// DefaultAggregationMinBytes of zero publishes every entry the Top-K
	// bound admits regardless of size.
	DefaultAggregationMinBytes = 0
	// HealthPath lives here so Validate can reject a telemetry path that takes it.
	// The server package already depends on this one, so the reverse would cycle.
	HealthPath       = "/healthz"
	DefaultLogLevel  = "info"
	DefaultLogFormat = "json"
)

// Config represents the complete configuration.
type Config struct {
	Web               Web               `json:"web"`
	Receiver          Receiver          `json:"receiver"`
	Parser            Parser            `json:"parser"`
	Aggregation       Aggregation       `json:"aggregation"`
	Collectors        Collectors        `json:"collectors"`
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

// Receiver holds UDP flow receiver configuration.
type Receiver struct {
	Addresses     []string `json:"addresses"`
	BatchSize     int      `json:"batch_size"`
	QueueSize     int      `json:"queue_size"`
	SockBufBytes  int      `json:"sock_buf_bytes"`
	MaxPacketSize int      `json:"max_packet_size"`
	Workers       int      `json:"workers"`
}

// Parser holds the protocol parser limits.
type Parser struct {
	MaxFieldsPerTemplate int           `json:"max_fields_per_template"`
	TemplateTTL          time.Duration `json:"template_ttl"`
}

// Aggregation holds the in-memory aggregation limits.
type Aggregation struct {
	EntryTTL   time.Duration `json:"entry_ttl"`
	MaxEntries int           `json:"max_entries"`
	TopK       int           `json:"top_k"`
	MinBytes   int64         `json:"min_bytes"`
}

// Collectors holds the data collector module switches. Every module is off
// by default: an exporter with none enabled receives and counts flows but
// publishes no traffic series.
type Collectors struct {
	Exporters     bool `json:"exporters"`
	Hosts         bool `json:"hosts"`
	Services      bool `json:"services"`
	ASNs          bool `json:"asns"`
	Applications  bool `json:"applications"`
	Distributions bool `json:"distributions"`
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
		Receiver: Receiver{
			Addresses:     cmd.StringSlice("receiver.address"),
			BatchSize:     cmd.Int("receiver.batch-size"),
			QueueSize:     cmd.Int("receiver.queue-size"),
			SockBufBytes:  cmd.Int("receiver.buffer-bytes"),
			MaxPacketSize: cmd.Int("receiver.max-packet-size"),
			Workers:       cmd.Int("receiver.workers"),
		},
		Parser: Parser{
			MaxFieldsPerTemplate: cmd.Int("parser.max-fields-per-template"),
			TemplateTTL:          cmd.Duration("parser.template-ttl"),
		},
		Aggregation: Aggregation{
			EntryTTL:   cmd.Duration("aggregation.entry-ttl"),
			MaxEntries: cmd.Int("aggregation.max-entries"),
			TopK:       cmd.Int("aggregation.top-k"),
			MinBytes:   cmd.Int64("aggregation.min-bytes"),
		},
		Collectors: Collectors{
			Exporters:     cmd.Bool("collector.exporters"),
			Hosts:         cmd.Bool("collector.hosts"),
			Services:      cmd.Bool("collector.services"),
			ASNs:          cmd.Bool("collector.asns"),
			Applications:  cmd.Bool("collector.applications"),
			Distributions: cmd.Bool("collector.distributions"),
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

	if err := c.validateReceiver(); err != nil {
		return fmt.Errorf("receiver validation failed: %w", err)
	}

	if err := c.validateParser(); err != nil {
		return fmt.Errorf("parser validation failed: %w", err)
	}

	if err := c.validateAggregation(); err != nil {
		return fmt.Errorf("aggregation validation failed: %w", err)
	}

	return nil
}

// validateAggregation validates the aggregation limits.
func (c *Config) validateAggregation() error {
	a := &c.Aggregation

	validationRules := []struct {
		condition bool
		message   string
	}{
		{
			a.EntryTTL <= 0,
			fmt.Sprintf("aggregation entry TTL must be positive, got: %v", a.EntryTTL),
		},
		{
			a.MaxEntries < 1,
			fmt.Sprintf("invalid aggregation max entries: %d (must be positive)", a.MaxEntries),
		},
		{
			a.TopK < 1,
			fmt.Sprintf("invalid aggregation top-k: %d (must be positive)", a.TopK),
		},
		{
			a.MinBytes < 0,
			fmt.Sprintf("invalid aggregation min bytes: %d (must not be negative)", a.MinBytes),
		},
	}

	for _, rule := range validationRules {
		if rule.condition {
			return errors.New(rule.message)
		}
	}

	return nil
}

// validateParser validates the protocol parser limits.
func (c *Config) validateParser() error {
	// maxTemplateFields is the most fields one template may ever declare: a
	// record must fit a flowset, whose length field caps it at 65535 bytes.
	const maxTemplateFields = 16383

	p := &c.Parser

	validationRules := []struct {
		condition bool
		message   string
	}{
		{
			p.MaxFieldsPerTemplate < 1 || p.MaxFieldsPerTemplate > maxTemplateFields,
			fmt.Sprintf("invalid parser max fields per template: %d (must be 1-%d)",
				p.MaxFieldsPerTemplate, maxTemplateFields),
		},
		{
			p.TemplateTTL <= 0,
			fmt.Sprintf("parser template TTL must be positive, got: %v", p.TemplateTTL),
		},
	}

	for _, rule := range validationRules {
		if rule.condition {
			return errors.New(rule.message)
		}
	}

	return nil
}

// validateReceiver validates the flow receiver configuration.
func (c *Config) validateReceiver() error {
	const (
		maxBatchSize = 1024
		maxWorkers   = 256
		// minPacketSize is the IPv4 minimum reassembly buffer, below which no
		// conforming exporter can be expected to fit a message.
		minPacketSize = 576
		maxPacketSize = 65535
	)

	r := &c.Receiver

	validationRules := []struct {
		condition bool
		message   string
	}{
		{
			len(r.Addresses) == 0,
			"at least one receiver address is required (--receiver.address)",
		},
		{
			r.BatchSize < 1 || r.BatchSize > maxBatchSize,
			fmt.Sprintf("invalid receiver batch size: %d (must be 1-%d)", r.BatchSize, maxBatchSize),
		},
		{
			r.QueueSize < 1,
			fmt.Sprintf("invalid receiver queue size: %d (must be positive)", r.QueueSize),
		},
		{
			r.SockBufBytes < 0,
			fmt.Sprintf("invalid receiver buffer bytes: %d (must be 0 for the OS default, or positive)",
				r.SockBufBytes),
		},
		{
			r.MaxPacketSize < minPacketSize || r.MaxPacketSize > maxPacketSize,
			fmt.Sprintf("invalid receiver max packet size: %d (must be %d-%d)",
				r.MaxPacketSize, minPacketSize, maxPacketSize),
		},
		{
			r.Workers < 0 || r.Workers > maxWorkers,
			fmt.Sprintf("invalid receiver workers: %d (must be 0 for auto, or 1-%d)", r.Workers, maxWorkers),
		},
	}

	for _, rule := range validationRules {
		if rule.condition {
			return errors.New(rule.message)
		}
	}

	seen := make(map[string]bool, len(r.Addresses))
	for _, address := range r.Addresses {
		if err := validateReceiverAddress(address); err != nil {
			return err
		}
		if seen[address] {
			return errors.New("duplicate receiver address: " + address)
		}
		seen[address] = true
	}

	return nil
}

// validateReceiverAddress checks one host:port a listener binds.
func validateReceiverAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid receiver address %q: %w", address, err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid receiver address %q: port must be 1-65535", address)
	}

	// An empty host binds every interface. A non-empty one must be an IP
	// address: resolving names at validation time would make startup depend on
	// a resolver, and a listener wants an interface rather than a peer.
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid receiver address %q: host must be an IP address or empty", address)
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
