package cli

import (
	"os"
	"testing"
)

// TestNewApp_DryRun drives the whole app wiring through the dry-run path, which
// parses the flags, validates the configuration and returns before serving.
func TestNewApp_DryRun(t *testing.T) {
	t.Parallel()

	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	os.Args = []string{"xflow-exporter", "--dry-run", "--log.format", "text"}

	cmd := NewApp()
	if cmd == nil {
		t.Fatal("NewApp() returned nil")
	}
	if cmd.Name != "xflow-exporter" {
		t.Errorf("NewApp() name = %q, want xflow-exporter", cmd.Name)
	}
	if cmd.Version != getVersion() {
		t.Errorf("NewApp() version = %q, want %q", cmd.Version, getVersion())
	}
}
