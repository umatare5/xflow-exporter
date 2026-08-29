package cli

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// parseWith runs config.Parse against the flags this package declares, driven
// by a real command line.
func parseWith(t *testing.T, args ...string) *config.Config {
	t.Helper()

	var cfg *config.Config
	var parseErr error
	cmd := &cli.Command{
		Name:  "xflow-exporter",
		Flags: registerFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			cfg, parseErr = config.Parse(cmd)
			return parseErr
		},
	}
	if err := cmd.Run(context.Background(), append([]string{"xflow-exporter"}, args...)); err != nil {
		t.Fatalf("Run(%v) error = %v", args, err)
	}
	return cfg
}

// TestFlagNamesReachTheConfiguration pins every declared flag to a field
// config.Parse reads. The two surfaces name each flag independently -- one
// declares the string, the other passes it to cmd.String -- and urfave/cli
// answers an unknown name with a zero value rather than an error. A rename on
// one side alone therefore compiles, starts, validates and silently discards
// whatever the operator set, which no test that builds its own flag set can
// see.
func TestFlagNamesReachTheConfiguration(t *testing.T) {
	t.Parallel()

	defaults := parseWith(t)

	// A few flags are validated as they are parsed, so their sentinel has to
	// be well formed as well as different.
	wellFormed := map[string]string{
		"web.listen-address":    "127.0.0.9",
		"receiver.address":      ":29999",
		"web.telemetry-path":    "/xflow-sentinel",
		"log.level":             "debug",
		"log.format":            "text",
		"remote-write.url":      "http://xflow-sentinel.invalid/write",
		"remote-write.header":   "X-Xflow-Sentinel=1",
		"remote-write.username": "xflow-sentinel",
	}

	for _, flag := range registerFlags() {
		name := flag.Names()[0]

		var arg string
		switch f := flag.(type) {
		case *cli.BoolFlag:
			arg = "--" + name
		case *cli.IntFlag:
			arg = "--" + name + "=" + strconv.Itoa(f.Value+7)
		case *cli.Int64Flag:
			arg = "--" + name + "=" + strconv.FormatInt(f.Value+7, 10)
		case *cli.DurationFlag:
			arg = "--" + name + "=" + (f.Value + 7).String()
		case *cli.StringFlag, *cli.StringSliceFlag:
			value, ok := wellFormed[name]
			if !ok {
				value = "xflow-sentinel"
			}
			arg = "--" + name + "=" + value
		default:
			t.Fatalf("%s: unhandled flag type %T, add it here rather than skipping it", name, flag)
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := parseWith(t, arg); reflect.DeepEqual(got, defaults) {
				t.Errorf("%s changed no field of the parsed configuration:\n"+
					"the name this package declares is not the name config.Parse reads", arg)
			}
		})
	}
}

// TestFlagNamesAreStable names every flag this exporter accepts. A rename is a
// breaking change to a command line an operator has written down, so it is
// meant to be a deliberate edit here rather than a silent consequence.
func TestFlagNamesAreStable(t *testing.T) {
	t.Parallel()

	want := map[string]bool{
		"web.listen-address": true, "web.listen-port": true, "web.telemetry-path": true,
		"web.enable-lifecycle": true,
		"receiver.address":     true, "receiver.batch-size": true, "receiver.queue-size": true,
		"receiver.buffer-bytes": true, "receiver.max-packet-size": true, "receiver.workers": true,
		"parser.max-fields-per-template": true, "parser.template-ttl": true,
		"aggregation.entry-ttl": true, "aggregation.max-entries": true,
		"aggregation.top-k": true, "aggregation.min-bytes": true,
		"collector.exporters": true, "collector.hosts": true, "collector.services": true,
		"collector.destinations": true, "collector.tcp-flags": true, "collector.dscp": true,
		"collector.asns": true, "collector.applications": true, "collector.countries": true,
		"collector.threats": true, "collector.distributions": true,
		"collector.internal.go-runtime": true, "collector.internal.process": true,
		"enrich.services": true, "enrich.asn-database": true, "enrich.country-database": true,
		"enrich.threat-file": true,
		"remote-write.url":   true, "remote-write.interval": true, "remote-write.timeout": true,
		"remote-write.username": true, "remote-write.password": true, "remote-write.header": true,
		"log.level": true, "log.format": true,
		"dry-run": true,
	}

	got := map[string]bool{}
	for _, flag := range registerFlags() {
		got[flag.Names()[0]] = true
	}

	for name := range want {
		if !got[name] {
			t.Errorf("flag %q is no longer declared", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("flag %q is new; add it here and to docs/configuration.md", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d flags declared, %d named here", len(got), len(want))
	}
}
