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
			Usage:    "Largest datagram in bytes kept whole; larger ones are dropped",
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
