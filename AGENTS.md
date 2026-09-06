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
- `docs/` — the reference set: `README.md` for the shared rules, `collectors.md` and `health.md` for the catalogues, `enrichment.md` for the operator's files, `help.md` for the flags, `protocols.md` for the wire
- `examples/` — scrape config, record and alert rules with tests, a mapping file and a dashboard

## Setup and Commands

Install these once: `go install gotest.tools/gotestsum@latest`, then [`golangci-lint`](https://golangci-lint.run/docs/welcome/install/local/), [`gitleaks`](https://github.com/gitleaks/gitleaks#installing) and [`pre-commit`](https://pre-commit.com/#install) from their own install documentation.

`make pre-commit-install` wires [`scripts/no-commit-to-main.sh`](scripts/no-commit-to-main.sh), `golangci-lint`, `actionlint`, `gitleaks` and `markdownlint-cli2` (see [`.pre-commit-config.yaml`](.pre-commit-config.yaml)).

Only `gitleaks` is taken from `PATH`, because pre-commit builds the rest at the versions the config pins, and the markdown hook runs with `--fix`. The branch guard runs first and carries `fail_fast`, so a commit on `main` stops at that hook rather than paying for the linters. Work on a branch.

Make targets ([`Makefile`](Makefile)), listed with the tools they need by `make help`.

- `make build` — Build binary into `tmp/xflow-exporter`
- `make lint` — `golangci-lint run` + `go mod tidy`
- `make test-unit` — Run unit tests via `gotestsum` with coverage
- `make test-unit-coverage` — Generate HTML report at `coverage/report.html`
- `make clean` — Remove build artifacts and `.bak*` files
- `make image` — Build Docker image (`$USER/xflow-exporter`)
- `make pre-commit-test` — Run every hook across the tree without committing
- `make pre-commit-uninstall` — Remove the hooks

Reach markdown style through `make pre-commit-test`, not the `markdownlint-cli2` on `PATH`. Links are checked in CI only, because that run reaches third-party hosts, and `lychee .` reproduces it locally, discovering [`lychee.toml`](lychee.toml) on its own.

[`CONTRIBUTING.md`](CONTRIBUTING.md#development) carries the tool setup, what a target does beyond its name and what CI runs.

## Code Style

- `golangci-lint` enforces linting and formatting in the pre-commit hook (see [`.golangci.yml`](.golangci.yml)).
- Comments record only what the code cannot say, and never address the reader.
- Keep minimal for all changes, coding, testing, commenting, and documentation.
- Call the unit a `--collector.<name>` flag switches a collector, a named series group a family, and the aggregation mechanism a table. `module` is not used.

## Testing

- Run `make test-unit` before committing.
- Place tests next to code under test (`*_test.go`).
- Coverage threshold is enforced by [`.github/workflows/go-test-coverage.yml`](.github/workflows/go-test-coverage.yml).
- Check a new test by mutation: reverse the change it pins and watch it fail, because a test that passes either way pins nothing (see [`CONTRIBUTING.md`](CONTRIBUTING.md#testing)).

## Commits and PRs

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore(deps):`, etc.).
- Sign off commits with `Signed-off-by:` (DCO).
- Open PRs against `main`. CI runs lint, the tests with race detection and a coverage threshold, CodeQL, `govulncheck`, and `promtool` over the example rules and scrape config.

## Domain Knowledge

A claim about a device is written only after its own export was decoded. See [`CONTRIBUTING.md`](CONTRIBUTING.md#documentation) for the rule and [`docs/protocols.md`](docs/protocols.md) for the devices it was applied to.

The invariants every decoder and collector keeps, each owned by the page it links:

- **A flow field the device did not report must produce no series** — never `0`, `false`, `NaN` or an epoch timestamp, because Prometheus cannot tell a fabricated zero from a measured one. See [Absence](docs/README.md#absence).
- **A template is valid only inside the exporter address, protocol and observation domain that announced it** — keying by any subset corrupts records when two domains reuse one template ID. See [Protocols](docs/protocols.md#netflow-v9-and-ipfix).
- **Anything that counts or publishes a domain carries the protocol** — a domain is `exporter_address`, `version` and `odid`, so dropping one hands two domains one label set. See [Exporter health](docs/health.md#specifications).
- **Byte and packet counts on a sampled export are per-sample readings** — series carry the corrected value and the rate in force, so a correction is auditable. See [Sampling correction](docs/README.md#sampling-correction).

What the exporting devices do, which the decoders and the pages are written around:

- **One device may export two protocols from one address** — numbering both protocols' templates from 256 in one domain, as a Catalyst 9800-CL does, so the key carries the protocol. See [Protocols](docs/protocols.md#netflow-v9-and-ipfix).
- **Devices re-announce templates on their own timer** — `missing_template` after an exporter restart is expected until every device has done so, and an alert on it waits. See [Exporter health](docs/health.md#specifications).
- **Flexible NetFlow flushes its cache in bursts** — the receive buffer and the queue are sized for the storm rather than the average. See [Help](docs/help.md#notes).
- **A device may accept a collect statement it cannot honour** — it exports `0` for the field, which NetFlow Lite platforms do for the output interface. See [Collectors](docs/collectors.md#labels).
- **A device's own parse wins over a packet section** — no verified device exports a section, so that path is covered by fixtures alone. See [Protocols](docs/protocols.md#packet-sections).
