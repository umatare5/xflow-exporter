package main

import (
	"os"
	"testing"
)

// TestMain_CanCall drives main through --dry-run, which parses and validates
// without serving.
func TestMain_CanCall(t *testing.T) {
	t.Parallel()

	originalArgs := os.Args

	defer func() {
		os.Args = originalArgs

		if r := recover(); r != nil {
			t.Fatalf("main() panic: %v", r)
		}
	}()

	os.Args = []string{"xflow-exporter", "--dry-run"}

	main()
}
