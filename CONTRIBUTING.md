# Contributing

## Development

Install [`gotestsum`](https://github.com/gotestyourself/gotestsum), [`golangci-lint`](https://golangci-lint.run/docs/welcome/install/local/), [`pre-commit`](https://pre-commit.com/#install) and [`gitleaks`](https://github.com/gitleaks/gitleaks#installing), then run `make pre-commit-install`.

| Command                     | Description                                  |
| :-------------------------- | :------------------------------------------- |
| `make help`                 | Display available targets and requirements   |
| `make build`                | Build the binary to `./tmp/xflow-exporter`   |
| `make lint`                 | Run golangci-lint and tidy go.mod            |
| `make test-unit`            | Run unit tests with coverage using gotestsum |
| `make test-unit-coverage`   | Generate the HTML coverage report            |
| `make clean`                | Remove the build and coverage artifacts      |
| `make image`                | Build the Docker image                       |
| `make pre-commit-install`   | Install the pre-commit hooks                 |
| `make pre-commit-test`      | Run every hook across the tree               |
| `make pre-commit-uninstall` | Remove the pre-commit hooks                  |

- **Hook order** — the branch guard, `golangci-lint`, `actionlint`, `gitleaks`, then `markdownlint-cli2`.
- **The guard carries `fail_fast`** — a commit on `main` stops there, so work on a branch.
- **Only `gitleaks` comes from `PATH`** — pre-commit builds the rest at the versions it pins.
- **The markdown hook runs `--fix`** — it rewrites files, so reach it with `make pre-commit-test`.
- **`make build` skips a rebuild** — the file target does nothing while `./tmp/xflow-exporter` exists.
- **`make clean` takes `./tmp` whole** — worktrees and fetched enrichment data go with the binary.

CI runs Format and Lint, Test and Build, Coverage, Prometheus Rules, markdownlint, Link Check, actionlint, CodeQL and govulncheck on every pull request.

## Build

`make image` cross-compiles a Linux binary for the host architecture into `./tmp/image/linux/<arch>`, then builds from `./tmp/image`, because the `Dockerfile` expects the GoReleaser layout of a binary beside `LICENSE` and `NOTICE`.

- **Tag and ports** — `$USER/xflow-exporter`, declaring 10053 and 4739/udp without publishing them.
- **Image contents** — `scratch`, UID 65534 and one CA bundle the remote-write client alone uses.
- **Released images** — GoReleaser pushes `amd64` and `arm64` to `ghcr.io/umatare5/xflow-exporter`.

## Testing

`make test-unit` runs every package under `gotestsum` with `-race` and a coverage profile, and CI runs the same against a threshold of 80 percent.

- **Placement** — a test is a `*_test.go` beside the code, named for the behaviour it pins.
- **Mutation** — check a new test by reversing the change it pins and watching it fail.
- **Fixtures** — a datagram is laid out as a device lays it out, and its addresses come from the RFC 5737 documentation ranges or RFC 1918, never from a monitored network or a real device.
- **One skip is normal** — a test skips unless `XFLOW_TEST_ASN_DATABASE` names a MaxMind database.

The example rules are linted and unit-tested in CI by `promtool`, which no hook covers.

```bash
promtool check rules --lint all --lint-fatal examples/prometheus_*_rules.yml
promtool test rules examples/prometheus_*_rules_test.yml
promtool check config --lint all --lint-fatal examples/prometheus.yml
```

## Code Style

`golangci-lint` enforces what [`.golangci.yml`](.golangci.yml) configures. A comment records only what the code cannot say, and every change stays minimal — [`AGENTS.md`](AGENTS.md#code-style) carries both rules.

A `--collector.<name>` flag switches a collector, a named series group is a family, and a table is the aggregation mechanism behind a collector. A HELP string is one sentence stating the reading of one series, as in `Sampling-corrected bytes per exporter and version, other carries the entry-bound fold`.

## Documentation

Every fact has one page that owns it, and the other pages link to it rather than restating it.

| Page                                      | Owns                                      |
| :---------------------------------------- | :---------------------------------------- |
| `README.md`                               | What it is, how to run and scrape it      |
| `docs/README.md`                          | The rules every collector obeys           |
| `docs/collectors.md` and `docs/health.md` | The metric catalogues                     |
| `docs/enrichment.md`                      | The files an operator supplies            |
| `docs/help.md`                            | The verbatim `--help` transcript          |
| `docs/protocols.md`                       | The wire formats and the verified devices |

- **Headings are pinned** — [`.markdownlint-cli2.jsonc`](.markdownlint-cli2.jsonc) fixes each page's `#` and `##` headings in order, so a heading change ships with its contract in the same pull request.
- **A device claim is read off a wire** — `docs/protocols.md` names the device in `Verified on`.
- **Links are checked in CI only** — that run reaches third-party hosts, and `lychee .` reproduces it.

## Release

1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [vX.Y.Z]` and add that version's link at the foot.
2. Update the version in the `VERSION` file.
3. Update the `VERSION:` line in the `--help` transcript in `docs/help.md`.

Merging one pull request with all three files starts the release. A push to `main` touching `VERSION` tags the commit, pushes the container images and uploads the artifacts to a draft release.

- **The images go public before the draft** — discarding the draft withdraws none of them.
- **A prerelease tag pushes no image** — its draft carries the archives alone.
- **The release links 404 until the merge** — [`lychee.toml`](lychee.toml) excludes the tag and compare patterns.
- **There is no manual trigger** — the push runs it, and a weekly snapshot build tags nothing.

## Pull Requests

1. [Fork](https://github.com/umatare5/xflow-exporter/fork) the repository and create a feature branch.
2. Commit with a [Conventional Commits](https://www.conventionalcommits.org/) subject and a `Signed-off-by:` trailer.
3. Record the change under `## [Unreleased]` in `CHANGELOG.md`, rebase against `main`, then open the PR.

Nothing in a commit identifies a monitored network or carries a credential.

- **`gitleaks` reads shapes** — its rules catch a token or a key, so addresses are your own care.
- **Captures live under `tmp/`** — git, the Docker context, the linter and `air` all ignore it.
- **Credentials stay in the environment** — `.env` and `.envrc` are git-ignored, so the two `XFLOW_REMOTE_WRITE_*` variables belong there rather than in a committed file.
- **Advisories need a path** — `govulncheck` and CodeQL run weekly, and a report names the call path from `./cmd` that reaches the finding rather than the advisory alone.
