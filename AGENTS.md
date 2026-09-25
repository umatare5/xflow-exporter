# Repository Instructions

> [!IMPORTANT]
> Read [`README.md`](README.md) for project overview.

## Tech Stack

- Go 1.27+ (see [`go.mod`](go.mod))
- [`prometheus/client_golang`](https://github.com/prometheus/client_golang) v1.24+ — metric registration and HTTP handler
- [`urfave/cli/v3`](https://github.com/urfave/cli) v3.11+ — CLI flags and application lifecycle
- [`goreleaser`](https://goreleaser.com/) v2 — cross-platform release builds (see [`.goreleaser.yml`](.goreleaser.yml))

## Repository Structure

Read from `cmd/main.go`. Each package is named for what it owns.

- [`cmd/main.go`](cmd/main.go) – application entry point
- [`internal/cli/`](internal/cli) – command-line flags, defaults and app wiring
- [`internal/config/`](internal/config) – flag reads and configuration validation
- [`internal/receiver/`](internal/receiver) – UDP listeners and the bounded ingest queue
- [`internal/decoder/`](internal/decoder) – datagram parsing, template cache and sampling
- [`internal/flow/`](internal/flow) – the normalized record every decoder produces
- [`internal/enrich/`](internal/enrich) – label fills from the local enrichment sources
- [`internal/aggregator/`](internal/aggregator) – bounded in-memory tables and their sweeps
- [`internal/collector/`](internal/collector) – metric descriptions and collection logic
- [`internal/server/`](internal/server) – HTTP server, routing and process lifecycle
- [`internal/remotewrite/`](internal/remotewrite) – Remote Write 2.0 client for the registry
- [`internal/pool/`](internal/pool) – type-safe buffer pool the receive path reuses
- [`internal/log/`](internal/log) – logger setup
- [`docs/`](docs) – reference pages behind the README
- [`scripts/`](scripts) – helper scripts the pre-commit hooks run
- [`examples/`](examples) – Prometheus configuration, rules and the Grafana dashboard

## Setup and Commands

Run `make pre-commit-install` first.

- Read [`Makefile`](Makefile) which lists all available make targets and their descriptions.
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) which provides guidelines for contributing to the project.

## Code Style

Follow [Effective Go](https://go.dev/doc/effective_go) conventions and the software development principles DRY/YAGNI/SRP.

- Keep code simple and readable, avoiding clever tricks that obscure intent.
- Keep minimal for all changes, coding, testing, commenting, and documentation.
- Write simple comments that explain the reasoning behind the code, not just what it does.

## Testing

Follow [`CONTRIBUTING.md`](CONTRIBUTING.md).

- Run `make test-unit` before creating a commit.
- One snapshot backs every collector test – see [`CONTRIBUTING.md`](CONTRIBUTING.md) for why a private one hides absence.

## Commits and PRs

Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore(deps):`, etc.).

- Run pre-commit and ensure all hooks pass before committing.
- Must Sign off all commits with `Signed-off-by:` (DCO).
- Open PRs against `main`. Create Draft PR as default.

## Domain Knowledge

Learn the constraints related to external entities, such as network devices, protocols, and enrichment sources.

### About the protocol

How the protocol operates and the expectations for devices and collectors. See also [Protocols](docs/protocols.md).

- **Flexible NetFlow flushes its cache in bursts** — the receive buffer and the queue are sized for the storm rather than the average. See [Help](docs/help.md#technical-notes).
- **A flow field the device did not report must produce no series** — never `0`, `false`, `NaN` or an epoch timestamp, because Prometheus cannot tell a fabricated zero from a measured one. See [Absence](docs/architecture.md#absence).
- **A template is valid only inside the exporter address, protocol and observation domain that announced it** — keying by any subset corrupts records when two domains reuse one template ID. See [Protocols](docs/protocols.md#netflow-v9).
- **Anything that counts or publishes a domain carries the protocol** — a domain is `exporter_address`, `version` and `odid`, so dropping one hands two domains one label set. See [Exporter health](docs/health.md#technical-notes).
- **Byte and packet counts on a sampled export are per-sample readings** — series carry the corrected value and the rate in force, so a correction is auditable. See [Sampling correction](docs/architecture.md#sampling-correction).

### About the network devices

How the network devices behave and interact with the collectors. See also [Collectors](docs/collectors.md).

- **One device may export two protocols from one address** — numbering both protocols' templates from 256 in one domain, as a Catalyst 9800-CL does, so the key carries the protocol. See [Protocols](docs/protocols.md#netflow-v9).
- **Devices re-announce templates on their own timer** — `missing_template` after an exporter restart is expected until every device has done so, and an alert on it waits. See [Exporter health](docs/health.md#annotations).
- **A device may accept a collect statement it cannot honor** — it exports `0` for the field, which NetFlow Lite platforms do for the output interface. See [Collectors](docs/collectors.md#labels).
- **A device's own parse wins over a packet section** — no verified device exports a section, so that path is covered by fixtures alone. See [Protocols](docs/protocols.md#packet-sections).
- **A sampling agent drops the samples it marked** — the rate in force is then not the rate delivered, and the agent's own counters are what say so. See [Exporter health](docs/health.md#technical-notes).

### About the Enrichments

How the source of the enrichment data behaves and interacts with the collectors. See also [Enrichment](docs/enrichment.md).

- **Every enrichment source is a file on local disk** – a lookup reads memory and fetches nothing, so an absent source leaves the label unfilled rather than failing the scrape. See [Enrichment](docs/enrichment.md#sources).
- **A reload swaps a source whole** – the new set is built before it replaces the old, and a source that fails to load keeps what it held, so no lookup sees a partial file. See [Enrichment](docs/enrichment.md#sources).
- **A line naming no address is skipped rather than fatal** – `xflow_threat_skipped_lines` counts them, a CIDR prefix included, so a list that loaded is not a list that matched. See [Threat lists](docs/enrichment.md#threat-lists).
