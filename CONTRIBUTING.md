# Contributing

Thank you for considering a contribution.

## Development

Install the tools once, then let the hooks run on every commit.

- `go install gotest.tools/gotestsum@latest`
- `golangci-lint` — see <https://golangci-lint.run/docs/welcome/install/local/>
- `pre-commit` — see <https://pre-commit.com/#install>
- `gitleaks` — see <https://github.com/gitleaks/gitleaks#installing>

`make pre-commit-install` wires the hooks [`.pre-commit-config.yaml`](.pre-commit-config.yaml) declares, in this order: the branch guard, `golangci-lint`, `actionlint`, `gitleaks` and `markdownlint-cli2`. The guard carries `fail_fast`, so a commit on `main` stops there rather than paying for the linters — work on a branch.

Only `gitleaks` is taken from `PATH`, because pre-commit builds the rest at the versions the config pins. The markdown hook runs with `--fix`, so it rewrites a file rather than only reporting it, and `make pre-commit-test` is how to reach that style rather than whichever `markdownlint-cli2` sits on `PATH`.

The following `make` commands are available for development and testing:

| Command                     | Description                                  |
| :-------------------------- | :------------------------------------------- |
| `make help`                 | Display available targets and requirements   |
| `make build`                | Build the binary to `./tmp/xflow-exporter`   |
| `make lint`                 | Run golangci-lint and tidy go.mod            |
| `make test-unit`            | Run unit tests with coverage using gotestsum |
| `make test-unit-coverage`   | Generate HTML coverage report                |
| `make clean`                | Remove build artifacts and backup files      |
| `make image`                | Build Docker image                           |
| `make pre-commit-install`   | Install the pre-commit hooks                 |
| `make pre-commit-test`      | Run every hook across the tree               |
| `make pre-commit-uninstall` | Remove the pre-commit hooks                  |

Two targets do what the table cannot say. `make build` is a file target, so it does nothing while `./tmp/xflow-exporter` exists, whatever changed since. `make clean` removes the whole `./tmp` tree, worktrees and fetched data included, not only the binary.

CI runs Format and Lint, Test and Build, Coverage, Prometheus Rules, markdownlint, Link Check, actionlint, CodeQL and govulncheck on every pull request.

## Build

The repository includes a ready to use `Dockerfile`. To build a new Docker image:

```bash
make image
```

This cross-compiles a Linux binary for the host architecture into `./tmp/image/linux/<arch>`, then builds from `./tmp/image`. The `Dockerfile` expects the GoReleaser context layout, `linux/<arch>/xflow-exporter` beside `LICENSE` and `NOTICE`. The image is tagged `$USER/xflow-exporter` and declares ports 10053 and 4739/udp without publishing them, so publish them with `docker run -p`.

The image is built from `scratch`, runs as UID 65534 and carries one CA bundle, which the remote-write client alone uses. Released images are pushed to `ghcr.io/umatare5/xflow-exporter` for `amd64` and `arm64` by GoReleaser instead.

## Testing

`make test-unit` runs every package under `gotestsum` with `-race` and a coverage profile, and CI runs the same with race detection on and a coverage threshold of 80 percent. One test skips unless `XFLOW_TEST_ASN_DATABASE` names a MaxMind-format ASN database, so one skip is the normal reading of a run.

- **Tests sit beside the code** — `*_test.go` in the package under test, named for the behaviour they pin rather than for a source file.
- **A new test is checked by mutation** — reverse the change it pins and watch it fail, because a test that passes either way pins nothing.
- **Fixtures carry real shapes** — a datagram is laid out as a device lays it out, with addresses from the RFC 5737 documentation ranges or RFC 1918.
- **The example rules are tested too** — CI lints and unit-tests them with `promtool`, which no hook covers.

Three commands reproduce the rule checks locally.

```bash
promtool check rules --lint all --lint-fatal examples/prometheus_record_rules.yml examples/prometheus_alert_rules.yml
```

```bash
promtool test rules examples/prometheus_record_rules_test.yml examples/prometheus_alert_rules_test.yml
```

```bash
promtool check config --lint all --lint-fatal examples/prometheus.yml
```

## Code style

`golangci-lint` enforces the style [`.golangci.yml`](.golangci.yml) configures, and the two rules no linter expresses are in [`AGENTS.md`](AGENTS.md#code-style): a comment records only what the code cannot say, and every change stays minimal.

A HELP string is one sentence stating the reading of one series, and a family that folds at the entry bound says so in it. `Sampling-corrected bytes per exporter and version, other carries the entry-bound fold` is the shape.

## Documentation

Every fact has one page that owns it, and the other pages link to it rather than restating it.

| Page                                      | Owns                                           |
| :---------------------------------------- | :--------------------------------------------- |
| `README.md`                               | What the exporter is, how to run and scrape it |
| `docs/README.md`                          | The rules every collector obeys                |
| `docs/collectors.md` and `docs/health.md` | The metric catalogues                          |
| `docs/enrichment.md`                      | The files an operator supplies                 |
| `docs/help.md`                            | The `--help` transcript and flag notes         |
| `docs/protocols.md`                       | The wire formats and the verified devices      |

- **The vocabulary is the ecosystem's** — a `--collector.<name>` flag switches a collector, a named series group is a family, and a table is the aggregation mechanism behind a collector.
- **Headings are pinned** — [`.markdownlint-cli2.jsonc`](.markdownlint-cli2.jsonc) lists each page's `#` and `##` in order with `*` between. A heading change ships with its contract in the same pull request.
- **The transcript is verbatim** — `docs/help.md` carries the binary's own `--help` output, and the release pull request refreshes its version line.
- **A device claim is read off a wire** — a sentence about what a device exports is written only after its own export was decoded, and the `Verified on` column in `docs/protocols.md` names which.
- **Links are checked in CI only** — that run reaches third-party hosts, so no hook covers it, and `lychee .` reproduces a failure locally.

## Release

To release a new version, follow these steps:

1. Rename the `## [Unreleased]` section in `CHANGELOG.md` to `## [vX.Y.Z]`, matching the version in the `VERSION` file, and add that version's release link at the foot of the file.
2. Update the version in the `VERSION` file.
3. Update the `VERSION:` line in the `--help` transcript in `docs/help.md`.
4. Submit a pull request with all three files.

Merging that pull request starts the release. A push to `main` touching `VERSION` runs the release workflow, which tags the commit, pushes the container images and uploads the artifacts to a draft release. Publishing that draft from the Releases page completes it.

- **The images are public before the draft is** — discarding the draft does not withdraw them.
- **A prerelease tag pushes no image** — the draft it leaves carries the archives alone.
- **The release links 404 until the merge** — [`lychee.toml`](lychee.toml) excludes the tag and compare patterns for that reason.
- **There is no manual trigger** — the workflow runs on the push alone, and a weekly snapshot build exercises every target without tagging.
- **Commit subjects group the release notes** — GoReleaser sorts `feat`, `fix` and `docs` under their own headings and drops `release:`, `ci:` and `test:`.

## Pull requests

1. [Fork](https://github.com/umatare5/xflow-exporter/fork) the repository
2. Create a feature branch, because the guard refuses a commit on `main`
3. Commit your changes with a [Conventional Commits](https://www.conventionalcommits.org/) subject and a `Signed-off-by:` trailer (DCO)
4. Record the pull request under the `## [Unreleased]` section in `CHANGELOG.md`, adding the section if it is not there yet
5. Rebase your local changes against the `main` branch
6. Create a new Pull Request

Nothing in a commit may identify a monitored network or carry a credential.

- **The hook scans for credential shapes** — `gitleaks` runs with its default rules, which recognise a token or a key and not an address, so addresses are your own care.
- **Fixtures use reserved ranges** — an address in a test comes from the RFC 5737 documentation ranges or RFC 1918, never from a monitored network or a real device.
- **Captures stay under `tmp/`** — the directory is ignored by git, the Docker context, the linter and `air`, so a datagram capture with real addresses lives there and nowhere else.
- **Credentials go in the environment** — `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD` stay out of a committed file, and `.env` and `.envrc` are ignored.
- **Dependencies are scanned in CI** — `govulncheck` and CodeQL run on every push and weekly, so report a finding with the path from `./cmd` that reaches it.
