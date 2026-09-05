package server

import (
	"os"
	"path/filepath"
	"testing"

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
