// Package cli provides the CLI implementation.
// This file holds the version string the linker stamps at build time.
package cli

var version = "dev"

func getVersion() string {
	return version
}
