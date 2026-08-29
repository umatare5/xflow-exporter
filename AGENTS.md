# Repository Instructions

> [!IMPORTANT]
> Read [README.md](README.md) for project overview and architecture.

## Tech Stack

- Go 1.27+ (see [go.mod](go.mod))
- [`prometheus/client_golang`](https://github.com/prometheus/client_golang) v1.24+ — metric registration and HTTP handler
- [`urfave/cli/v3`](https://github.com/urfave/cli) v3.11+ — CLI flags and application lifecycle
- [`goreleaser`](https://goreleaser.com/) v2 — cross-platform release builds (see [.goreleaser.yml](.goreleaser.yml))

## Repository Structure

- `cmd/` — Entry point (`main.go`); calls `internal/cli` for app setup
- `internal/cli/` — CLI flag definitions and app wiring (urfave/cli/v3)
- `internal/config/` — flag/env parsing, defaults (`0.0.0.0:10052`), and validation
- `internal/server/` — HTTP server (`/metrics`, `/healthz`, `/`), graceful shutdown
- `internal/collector/` — `prometheus.Collector` implementations and registry management
- `internal/log/` — `log/slog` setup; structured logging helpers

## Setup and Commands

Install required tools (one-time):

- `go install gotest.tools/gotestsum@latest`
- `golangci-lint` - See <https://golangci-lint.run/docs/welcome/install/local/>
- `goreleaser` release builds (see [.goreleaser.yml](.goreleaser.yml))
- `pre-commit install` wires `golangci-lint`, `gofmt`, `markdownlint-cli2`, `gitleaks` (see [.pre-commit-config.yaml](.pre-commit-config.yaml))

Make targets ([Makefile](Makefile)):

- `make build` — Build binary into `tmp/xflow-exporter`
- `make lint` — `golangci-lint run` + `go mod tidy`
- `make test-unit` — Run unit tests via `gotestsum` with coverage
- `make test-unit-coverage` — Generate HTML report at `coverage/report.html`
- `make clean` — Remove build artifacts and `.bak*` files
- `make image` — Build Docker image (`$USER/xflow-exporter`)

## Code Style

- `gofmt` and `golangci-lint` are enforced by the pre-commit hook (see [.pre-commit-config.yaml](.pre-commit-config.yaml)).
- Comments record only what the code cannot say; never address the reader.

## Testing Instructions

- Run `make test-unit` before committing.
- Place tests next to code under test (`*_test.go`).
- Coverage threshold is enforced by [.github/workflows/go-test-coverage.yml](.github/workflows/go-test-coverage.yml).

## Commits and PRs

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore(deps):`, etc.).
- Sign off commits with `Signed-off-by:` (DCO).
- Open PRs against `main`. CI runs lint, tests, and CodeQL.

## Domain Knowledge

### Absence

A flow field the device did not report must produce no series: never publish `0`,
`false`, `NaN` or an epoch timestamp for it. Prometheus cannot distinguish a
fabricated zero from a measured one.

### Template scope

NetFlow v9 and IPFIX templates are valid only within the transport session and
observation domain that announced them. Every template lookup is keyed by the
exporter source address and the Observation Domain ID (Source ID) together;
keying by either alone corrupts records when two domains reuse one template ID.

### Sampling

Byte and packet counts on a sampled export are per-sample readings. Published
series carry the sampling-corrected value, and the rate in force is itself
published so a correction is auditable.
