// Package cli provides the CLI implementation.
package cli

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/log"
	"github.com/umatare5/xflow-exporter/internal/server"
)

// NewApp creates a new CLI application.
func NewApp() *cli.Command {
	cmd := &cli.Command{
		Name:    "xflow-exporter",
		Usage:   "Prometheus exporter for NetFlow, IPFIX and sFlow",
		Version: getVersion(),
		Flags:   registerFlags(),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := config.Parse(cmd)
			if err != nil {
				slog.Error("Configuration parsing failed", "error", err)
				return errors.New("configuration error")
			}

			slog.SetDefault(log.Setup(cfg.Log))

			if cfg.DryRun {
				slog.Info("Configuration validation successful", "dry_run", true)
				return nil
			}

			return server.StartAndServe(ctx, cfg, getVersion())
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error("Application failed", "error", err)
		os.Exit(1)
	}
	return cmd
}

// registerFlags defines and returns all CLI flags organized by category.
func registerFlags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, registerWebFlags()...)
	flags = append(flags, registerReceiverFlags()...)
	flags = append(flags, registerParserFlags()...)
	flags = append(flags, registerAggregationFlags()...)
	flags = append(flags, registerCollectorFlags()...)
	flags = append(flags, registerEnrichmentFlags()...)
	flags = append(flags, registerRemoteWriteFlags()...)
	flags = append(flags, registerLogFlags()...)
	flags = append(flags, registerUtilityFlags()...)
	flags = append(flags, registerInternalCollectorFlags()...)
	return flags
}

// registerWebFlags defines flags for HTTP server configuration.
func registerWebFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "web.listen-address",
			Usage: "Address to bind the HTTP server to",
			Value: config.DefaultListenAddress,
		},
		&cli.IntFlag{
			Name:  "web.listen-port",
			Usage: "Port number to bind the HTTP server to",
			Value: config.DefaultListenPort,
		},
		&cli.StringFlag{
			Name:  "web.telemetry-path",
			Usage: "Path for the metrics endpoint",
			Value: config.DefaultTelemetryPath,
		},
		&cli.BoolFlag{
			Name:        "web.enable-lifecycle",
			Usage:       "Enable " + config.ReloadPath + ", which re-reads the enrichment sources",
			HideDefault: true,
		},
	}
}

// registerReceiverFlags defines flags for the UDP flow receiver.
func registerReceiverFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "receiver.address",
			Usage:    "Address to receive flow datagrams on (repeatable)",
			Value:    []string{config.DefaultReceiverAddress},
			Category: "* Receiver Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
		&cli.IntFlag{
			Name:     "receiver.batch-size",
			Usage:    "Maximum datagrams read per kernel round trip",
			Value:    config.DefaultReceiverBatchSize,
			Category: "* Receiver Options",
		},
		&cli.IntFlag{
			Name:     "receiver.queue-size",
			Usage:    "Datagrams buffered between the read loops and the decoders",
			Value:    config.DefaultReceiverQueueSize,
			Category: "* Receiver Options",
		},
		&cli.IntFlag{
			Name:     "receiver.buffer-bytes",
			Usage:    "UDP socket receive buffer size in bytes (0 keeps the OS default)",
			Value:    config.DefaultReceiverSockBufBytes,
			Category: "* Receiver Options",
		},
		&cli.IntFlag{
			Name:     "receiver.max-packet-size",
			Usage:    "Largest datagram in bytes kept whole, dropping larger ones",
			Value:    config.DefaultReceiverMaxPacketSize,
			Category: "* Receiver Options",
		},
		&cli.IntFlag{
			Name:     "receiver.workers",
			Usage:    "Decode workers consuming the queue (0 sizes to the CPU count)",
			Value:    config.DefaultReceiverWorkers,
			Category: "* Receiver Options",
		},
	}
}

// registerParserFlags defines flags for the protocol parser limits.
func registerParserFlags() []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:     "parser.max-fields-per-template",
			Usage:    "Most fields one NetFlow v9 or IPFIX template may declare",
			Value:    config.DefaultParserMaxFieldsPerTemplate,
			Category: "* Parser Options",
		},
		&cli.DurationFlag{
			Name:     "parser.template-ttl",
			Usage:    "How long an unrefreshed template stays usable",
			Value:    config.DefaultParserTemplateTTL,
			Category: "* Parser Options",
		},
	}
}

// registerAggregationFlags defines flags for the in-memory aggregation limits.
func registerAggregationFlags() []cli.Flag {
	return []cli.Flag{
		&cli.DurationFlag{
			Name:     "aggregation.entry-ttl",
			Usage:    "How long an idle aggregation entry keeps its series",
			Value:    config.DefaultAggregationEntryTTL,
			Category: "* Aggregation Options",
		},
		&cli.IntFlag{
			Name:     "aggregation.max-entries",
			Usage:    "Entry bound per aggregation table, folding new keys into other past it",
			Value:    config.DefaultAggregationMaxEntries,
			Category: "* Aggregation Options",
		},
		&cli.IntFlag{
			Name:     "aggregation.top-k",
			Usage:    "Entries each table publishes as their own series, folding the rest into other",
			Value:    config.DefaultAggregationTopK,
			Category: "* Aggregation Options",
		},
		&cli.Int64Flag{
			Name:     "aggregation.min-bytes",
			Usage:    "Bytes below which an entry folds into other at scrape time (0 publishes all)",
			Value:    config.DefaultAggregationMinBytes,
			Category: "* Aggregation Options",
		},
	}
}

// registerCollectorFlags defines the data collector module switches.
func registerCollectorFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "collector.exporters",
			Usage:       "Enable per-device traffic metrics",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.hosts",
			Usage:       "Enable source-destination address pair metrics",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.services",
			Usage:       "Enable address pair with protocol and port metrics",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.destinations",
			Usage:       "Enable destination address with protocol and port metrics",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.asns",
			Usage:       "Enable AS pair metrics from device-exported AS numbers",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.applications",
			Usage:       "Enable application metrics from AVC, App-ID or applicationId",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.countries",
			Usage:       "Enable country pair metrics, which need --enrich.country-database",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.threats",
			Usage:       "Enable flagged address metrics, which need --enrich.threat-file",
			Category:    "# Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.distributions",
			Usage:       "Enable flow size and duration native histograms",
			Category:    "# Collector Options",
			HideDefault: true,
		},
	}
}

// registerEnrichmentFlags defines the record enrichment switches.
func registerEnrichmentFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "enrich.services",
			Usage:       "Name the application from the transport port where the device named none",
			Category:    "# Enrichment Options",
			HideDefault: true,
		},
		&cli.StringFlag{
			Name:     "enrich.asn-database",
			Usage:    "Path to a MaxMind-format ASN database, filling the AS numbers a device omits",
			Category: "# Enrichment Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
		&cli.StringFlag{
			Name:     "enrich.country-database",
			Usage:    "Path to a MaxMind-format country database, filling the ISO codes for --collector.countries",
			Category: "# Enrichment Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
		&cli.StringSliceFlag{
			Name:     "enrich.threat-file",
			Usage:    "Path to a file of flagged addresses, one per line (repeatable)",
			Category: "# Enrichment Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
	}
}

// registerRemoteWriteFlags defines the Remote Write 2.0 client.
func registerRemoteWriteFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "remote-write.url",
			Usage:    "Remote Write 2.0 endpoint to ship metrics to, which enables the client when set",
			Category: "* Remote Write Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
		&cli.DurationFlag{
			Name:     "remote-write.interval",
			Usage:    "How often the registry is shipped",
			Value:    config.DefaultRemoteWriteInterval,
			Category: "* Remote Write Options",
		},
		&cli.DurationFlag{
			Name:     "remote-write.timeout",
			Usage:    "Timeout of one write",
			Value:    config.DefaultRemoteWriteTimeout,
			Category: "* Remote Write Options",
		},
		&cli.StringFlag{
			Name:     "remote-write.username",
			Usage:    "Basic auth username for the endpoint",
			Sources:  cli.EnvVars("XFLOW_REMOTE_WRITE_USERNAME"),
			Category: "* Remote Write Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
		&cli.StringFlag{
			Name:     "remote-write.password",
			Usage:    "Basic auth password for the endpoint",
			Sources:  cli.EnvVars("XFLOW_REMOTE_WRITE_PASSWORD"),
			Category: "* Remote Write Options",
		},
		&cli.StringSliceFlag{
			Name:     "remote-write.header",
			Usage:    "Extra request header as name=value (repeatable)",
			Category: "* Remote Write Options",
			Config: cli.StringConfig{
				TrimSpace: true,
			},
		},
	}
}

// registerLogFlags defines flags for logging configuration.
func registerLogFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "log.level",
			Usage: "Log level (debug, info, warn, error)",
			Value: config.DefaultLogLevel,
		},
		&cli.StringFlag{
			Name:  "log.format",
			Usage: "Log format (json, text)",
			Value: config.DefaultLogFormat,
		},
	}
}

// registerInternalCollectorFlags defines flags for internal metrics collection configuration.
func registerInternalCollectorFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "collector.internal.go-runtime",
			Usage:       "Enable Go runtime metrics collector",
			Category:    "* Internal Collector Options",
			HideDefault: true,
		},
		&cli.BoolFlag{
			Name:        "collector.internal.process",
			Usage:       "Enable process metrics collector",
			Category:    "* Internal Collector Options",
			HideDefault: true,
		},
	}
}

// registerUtilityFlags defines utility flags.
func registerUtilityFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "dry-run",
			Usage:       "Validate configuration without starting the server",
			HideDefault: true,
		},
	}
}
