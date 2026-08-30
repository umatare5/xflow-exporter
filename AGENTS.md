# Repository Instructions

> [!IMPORTANT]
> Read [`README.md`](README.md) for project overview and architecture.

## Tech Stack

- Go 1.27+ (see [`go.mod`](go.mod))
- [`prometheus/client_golang`](https://github.com/prometheus/client_golang) v1.24+ — metric registration and HTTP handler
- [`urfave/cli/v3`](https://github.com/urfave/cli) v3.11+ — CLI flags and application lifecycle
- [`goreleaser`](https://goreleaser.com/) v2 — cross-platform release builds (see [`.goreleaser.yml`](.goreleaser.yml))

## Repository Structure

- `cmd/` — Entry point (`main.go`), which calls `internal/cli` for app setup
- `internal/cli/` — CLI flag definitions and app wiring (urfave/cli/v3)
- `internal/config/` — flag/env parsing, defaults (`0.0.0.0:10053`), and validation
- `internal/receiver/` — UDP listeners and the datagram queue the decoders read
- `internal/decoder/` — NetFlow v5/v8/v9, IPFIX and sFlow v5 parsers, and the template store
- `internal/flow/` — the normalized record every decoder produces
- `internal/enrich/` — fills dimensions the device did not export, from local sources
- `internal/aggregator/` — bounded in-memory tables the collectors read at scrape time
- `internal/collector/` — `prometheus.Collector` implementations and registry management
- `internal/remotewrite/` — ships the registry to a Remote Write 2.0 endpoint
- `internal/pool/` — generic object pool used on the receive path
- `internal/server/` — HTTP server (`/metrics`, `/healthz`, `/-/reload`, `/`), graceful shutdown
- `internal/log/` — `log/slog` setup and structured logging helpers

## Setup and Commands

Install required tools (one-time):

- `go install gotest.tools/gotestsum@latest`
- `golangci-lint` - See <https://golangci-lint.run/docs/welcome/install/local/>
- `gitleaks` - See <https://github.com/gitleaks/gitleaks#installing>
- `pre-commit` - See <https://pre-commit.com/#install>
- `goreleaser` release builds (see [.goreleaser.yml](.goreleaser.yml))

`make pre-commit-install` wires `golangci-lint`, `gitleaks` and `markdownlint-cli2` (see [.pre-commit-config.yaml](.pre-commit-config.yaml)). Only `gitleaks` is taken from `PATH`, because pre-commit builds the other two at the versions the config pins. Reach markdown style through `make pre-commit-test`, not through whichever `markdownlint-cli2` sits on `PATH`.

Make targets ([Makefile](Makefile)):

- `make build` — Build binary into `tmp/xflow-exporter`
- `make lint` — `golangci-lint run` + `go mod tidy`
- `make test-unit` — Run unit tests via `gotestsum` with coverage
- `make test-unit-coverage` — Generate HTML report at `coverage/report.html`
- `make clean` — Remove build artifacts and `.bak*` files
- `make image` — Build Docker image (`$USER/xflow-exporter`)
- `make pre-commit-install` — Install the hooks from [.pre-commit-config.yaml](.pre-commit-config.yaml)
- `make pre-commit-test` — Run every hook across the tree without committing
- `make pre-commit-uninstall` — Remove the hooks

Markdown style is checked again in CI, and links are checked there only (see [.github/workflows/markdownlint.yml](.github/workflows/markdownlint.yml) and [.github/workflows/lychee.yml](.github/workflows/lychee.yml)). Links carry no hook, because the run reaches third-party hosts. `lychee .` reproduces that run locally and discovers [lychee.toml](lychee.toml) on its own.

## Code Style

- Linting and formatting are enforced by `golangci-lint` in the pre-commit hook (see [.golangci.yml](.golangci.yml)).
- Comments record only what the code cannot say, and never address the reader.
- Keep minimal for all changes, coding, testing, commenting, and documentation.

## Testing

- Run `make test-unit` before committing.
- Place tests next to code under test (`*_test.go`).
- Coverage threshold is enforced by [.github/workflows/go-test-coverage.yml](.github/workflows/go-test-coverage.yml).

## Commits and PRs

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore(deps):`, etc.).
- Sign off commits with `Signed-off-by:` (DCO).
- Open PRs against `main`. CI runs lint, tests and the alerting-rule checks.

## Domain Knowledge

### Absence

A flow field the device did not report must produce no series: never publish `0`,
`false`, `NaN` or an epoch timestamp for it. Prometheus cannot distinguish a
fabricated zero from a measured one.

### Template scope

NetFlow v9 and IPFIX templates are valid only within the transport session and
observation domain that announced them. Every template lookup is keyed by the
exporter source address, the protocol and the Observation Domain ID (Source ID)
together — keying by any subset corrupts records when two domains reuse one
template ID.

The protocol belongs in that key because RFC 7011's pair does not identify a
domain here. Three decoders share one store, each numbering templates from 256
in a space of its own, so a v9 Source ID, an IPFIX Observation Domain ID and an
sFlow sub-agent id collide freely — and a device exporting two protocols at
once sends both from one address.

Anything that counts or publishes a domain carries the protocol too. Dropping
it on the way out gives two domains one label set, and a registry refuses to
gather a duplicate: every series in the process is lost, not just the
domain's.

### Sampling

Byte and packet counts on a sampled export are per-sample readings. Published
series carry the sampling-corrected value, and the rate in force is itself
published so a correction is auditable.
