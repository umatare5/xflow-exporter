package server

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/aggregator"
	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// TestBuildEnrichmentChain_OperatorPortsWinOverTheBuiltInTable pins the order
// the two port tables sit in, which only this function decides. The operator
// wrote the mapping file to name what the built-in table gets wrong or does
// not carry, so a chain that ran the built-in table first would leave that
// file able to name nothing the table already claims -- and a test building
// its own chain inside package enrich would pass either way.
func TestBuildEnrichmentChain_OperatorPortsWinOverTheBuiltInTable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "mapping.yml")
	// The built-in table names 443/tcp https, so the two disagree here and
	// the chain order is what decides which name reaches the label.
	if err := os.WriteFile(path, []byte("services:\n  443/tcp: internal-portal\n"), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}

	chain, _, _, _, err := buildEnrichmentChain(config.Enrichment{Services: true, MappingFile: path})
	if err != nil {
		t.Fatalf("buildEnrichmentChain() error = %v, want nil", err)
	}
	defer chain.Close()

	records := []flow.Record{{Protocol: 6, SrcPort: 51234, DstPort: 443}}
	chain.Enrich(records)

	if records[0].AppName != "internal-portal" {
		t.Errorf("AppName = %q, want the mapping file's name ahead of the built-in table",
			records[0].AppName)
	}
}

// TestBuildEnrichmentChain_AMappingFileCarriesItsVLANs pins that the VLAN
// source is wired with the mapping file rather than behind a switch of its
// own, which only this function decides. It reads the snapshot that file
// owns, so a chain leaving it out would load a vlans block that reaches no
// record -- and a test building its own chain inside package enrich would
// pass either way.
func TestBuildEnrichmentChain_AMappingFileCarriesItsVLANs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "mapping.yml")
	document := "devices:\n  192.0.2.1:\n    vlans:\n      800:\n        prefixes: [10.0.0.0/24]\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}

	chain, _, _, _, err := buildEnrichmentChain(config.Enrichment{MappingFile: path})
	if err != nil {
		t.Fatalf("buildEnrichmentChain() error = %v, want nil", err)
	}
	defer chain.Close()

	records := []flow.Record{{
		Exporter: netip.MustParseAddr("192.0.2.1"),
		SrcAddr:  netip.MustParseAddr("10.0.0.7"),
		DstAddr:  netip.MustParseAddr("203.0.113.7"),
	}}
	chain.Enrich(records)

	if records[0].SrcVLAN != 800 || records[0].DstVLAN != 0 {
		t.Errorf("VLANs = %d -> %d, want 800 -> 0", records[0].SrcVLAN, records[0].DstVLAN)
	}
}

// TestValidateEnrichment pins that a dry run reaches the files the flags name.
// The flag promises a configuration is valid without starting the server, and
// a path that only startup opens is the mistake an operator most often makes
// and the one a pre-flight check exists to catch.
func TestValidateEnrichment(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.yml")
	if err := os.WriteFile(valid, []byte("devices:\n  192.0.2.1:\n    hostname: sw1\n"), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}
	duplicate := filepath.Join(dir, "duplicate.yml")
	if err := os.WriteFile(duplicate, []byte("devices:\n  192.0.2.1:\n  192.0.2.1:\n"), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}

	tests := []struct {
		name    string
		cfg     config.Enrichment
		wantErr bool
	}{
		{"nothing configured", config.Enrichment{}, false},
		{"a file that parses", config.Enrichment{MappingFile: valid}, false},
		{"a file that does not", config.Enrichment{MappingFile: duplicate}, true},
		{"a path that is not there", config.Enrichment{MappingFile: filepath.Join(dir, "absent.yml")}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateEnrichment(tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnrichment() error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

// TestAggregatorOptions_OperatorPortsReachTheAggregation pins the hand-off
// only this function makes. The built-in table names no internal service, so
// without it a site's own listener names an application and still leaves
// every reply leg keyed on the client's own port.
func TestAggregatorOptions_OperatorPortsReachTheAggregation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "mapping.yml")
	if err := os.WriteFile(path, []byte("services:\n  9100/tcp: node-exporter\n"), 0o600); err != nil {
		t.Fatalf("writing the mapping file: %v", err)
	}

	_, _, _, mapping, err := buildEnrichmentChain(config.Enrichment{MappingFile: path})
	if err != nil {
		t.Fatalf("buildEnrichmentChain() error = %v, want nil", err)
	}

	agg := aggregator.New(config.Aggregation{MaxEntries: 16, EntryTTL: time.Minute},
		aggregator.Modules{Destinations: true}, aggregatorOptions(mapping)...)
	agg.Ingest([]flow.Record{{
		Exporter: netip.MustParseAddr("192.0.2.1"),
		Protocol: 6, SrcPort: 9100, DstPort: 51234,
		DstAddr: netip.MustParseAddr("10.0.0.2"), Bytes: 100, Flows: 1,
	}})

	entries, _ := agg.Destinations()
	if len(entries) != 1 {
		t.Fatalf("Destinations() = %d entries, want 1", len(entries))
	}
	if entries[0].Key.Port != 9100 || entries[0].Key.Endpoint != aggregator.EndpointSrc {
		t.Errorf("keyed on port %d endpoint %s, want the file's 9100 as the source end",
			entries[0].Key.Port, entries[0].Key.Endpoint)
	}
}
