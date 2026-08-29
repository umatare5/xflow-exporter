package main

import (
	"os"
	"testing"
)

// TestMain_CanCall verifies that the main function can be called.
// This test uses dry-run mode to avoid actual server startup.
func TestMain_CanCall(t *testing.T) {
	t.Parallel()

	// Save original args
	originalArgs := os.Args

	defer func() {
		os.Args = originalArgs

		// Recover from potential panic or os.Exit
		if r := recover(); r != nil {
			t.Fatalf("main() panic: %v", r)
		}
	}()

	os.Args = []string{"xflow-exporter", "--dry-run"}

	// Call main function directly
	main()
}
