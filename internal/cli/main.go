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
