package cli

// version is the string the linker stamps at build time.
var version = "dev"

func getVersion() string {
	return version
}
