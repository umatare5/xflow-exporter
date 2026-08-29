package cli

import (
	"testing"

	"github.com/urfave/cli/v3"
)

// TestRegisterFlags verifies that registerFlags returns all flags from sub-registrars.
func TestRegisterFlags(t *testing.T) {
	t.Parallel()

	flags := registerFlags()
	if got, want := len(flags), 27; got != want {
		t.Errorf("registerFlags() returned %d flags, want %d", got, want)
	}
}

// TestRegisterWebFlags verifies web server configuration flags.
func TestRegisterWebFlags(t *testing.T) {
	t.Parallel()

	flags := registerWebFlags()
	if got, want := len(flags), 3; got != want {
		t.Fatalf("registerWebFlags() returned %d flags, want %d", got, want)
	}

	expectedTypes := []string{"string", "int", "string"}
	for i, flag := range flags {
		var gotType string
		switch flag.(type) {
		case *cli.StringFlag:
			gotType = "string"
		case *cli.IntFlag:
			gotType = "int"
		default:
			gotType = "unknown"
		}

		if gotType != expectedTypes[i] {
			t.Errorf("flag[%d] type = %s, want %s", i, gotType, expectedTypes[i])
		}
	}
}

// TestRegisterReceiverFlags verifies the UDP flow receiver flags.
func TestRegisterReceiverFlags(t *testing.T) {
	t.Parallel()

	flags := registerReceiverFlags()
	if got, want := len(flags), 6; got != want {
		t.Fatalf("registerReceiverFlags() returned %d flags, want %d", got, want)
	}

	if _, ok := flags[0].(*cli.StringSliceFlag); !ok {
		t.Errorf("flag[0] is %T, want *cli.StringSliceFlag", flags[0])
	}
	for i, flag := range flags[1:] {
		if _, ok := flag.(*cli.IntFlag); !ok {
			t.Errorf("flag[%d] is %T, want *cli.IntFlag", i+1, flag)
		}
	}
}

// TestRegisterParserFlags verifies the protocol parser limit flags.
func TestRegisterParserFlags(t *testing.T) {
	t.Parallel()

	flags := registerParserFlags()
	if got, want := len(flags), 2; got != want {
		t.Fatalf("registerParserFlags() returned %d flags, want %d", got, want)
	}
	if _, ok := flags[0].(*cli.IntFlag); !ok {
		t.Errorf("flag[0] is %T, want *cli.IntFlag", flags[0])
	}
	if _, ok := flags[1].(*cli.DurationFlag); !ok {
		t.Errorf("flag[1] is %T, want *cli.DurationFlag", flags[1])
	}
}

// TestRegisterAggregationFlags verifies the aggregation limit flags.
func TestRegisterAggregationFlags(t *testing.T) {
	t.Parallel()

	flags := registerAggregationFlags()
	if got, want := len(flags), 4; got != want {
		t.Fatalf("registerAggregationFlags() returned %d flags, want %d", got, want)
	}
	if _, ok := flags[0].(*cli.DurationFlag); !ok {
		t.Errorf("flag[0] is %T, want *cli.DurationFlag", flags[0])
	}
}

// TestRegisterCollectorFlags verifies the data collector module switches.
func TestRegisterCollectorFlags(t *testing.T) {
	t.Parallel()

	flags := registerCollectorFlags()
	if got, want := len(flags), 6; got != want {
		t.Fatalf("registerCollectorFlags() returned %d flags, want %d", got, want)
	}
	for i, flag := range flags {
		if _, ok := flag.(*cli.BoolFlag); !ok {
			t.Errorf("flag[%d] is %T, want *cli.BoolFlag", i, flag)
		}
	}
}

// TestRegisterEnrichmentFlags verifies the enrichment switches.
func TestRegisterEnrichmentFlags(t *testing.T) {
	t.Parallel()

	flags := registerEnrichmentFlags()
	if got, want := len(flags), 1; got != want {
		t.Fatalf("registerEnrichmentFlags() returned %d flags, want %d", got, want)
	}
	if _, ok := flags[0].(*cli.BoolFlag); !ok {
		t.Errorf("flag[0] is %T, want *cli.BoolFlag", flags[0])
	}
}

// TestRegisterLogFlags verifies logging configuration flags.
func TestRegisterLogFlags(t *testing.T) {
	t.Parallel()

	flags := registerLogFlags()
	if got, want := len(flags), 2; got != want {
		t.Fatalf("registerLogFlags() returned %d flags, want %d", got, want)
	}

	for i, flag := range flags {
		if _, ok := flag.(*cli.StringFlag); !ok {
			t.Errorf("flag[%d] is %T, want *cli.StringFlag", i, flag)
		}
	}
}

// TestRegisterInternalCollectorFlags verifies internal collector flags.
func TestRegisterInternalCollectorFlags(t *testing.T) {
	t.Parallel()

	flags := registerInternalCollectorFlags()
	if got, want := len(flags), 2; got != want {
		t.Fatalf("registerInternalCollectorFlags() returned %d flags, want %d", got, want)
	}

	for i, flag := range flags {
		if _, ok := flag.(*cli.BoolFlag); !ok {
			t.Errorf("flag[%d] is %T, want *cli.BoolFlag", i, flag)
		}
	}
}

// TestRegisterUtilityFlags verifies utility flags.
func TestRegisterUtilityFlags(t *testing.T) {
	t.Parallel()

	flags := registerUtilityFlags()
	if got, want := len(flags), 1; got != want {
		t.Fatalf("registerUtilityFlags() returned %d flags, want %d", got, want)
	}

	if _, ok := flags[0].(*cli.BoolFlag); !ok {
		t.Errorf("flag[0] is %T, want *cli.BoolFlag", flags[0])
	}
}

// TestRegisterFlags_NamesAreUnique verifies no flag name is registered twice.
func TestRegisterFlags_NamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for _, flag := range registerFlags() {
		for _, name := range flag.Names() {
			if seen[name] {
				t.Errorf("flag name %q is registered more than once", name)
			}
			seen[name] = true
		}
	}
}
