# Contributing

**[The shared contribution guide](https://github.com/umatare5/.github/blob/main/CONTRIBUTING.md)** defines the toolchain, the make targets and the conventions every exporter here shares.

This page specifies what is particular to this one: what CI enforces, how a fixture is built and which page owns which fact.

## Development

**The shared contribution guide** defines the general rules and conventions for contributing to this codebase.

- **Four checks are path-filtered** — govulncheck, markdownlint, Link Check and actionlint.
- **Coverage fails below 80 percent** — `make test-unit` writes the profile without judging it.
- **actionlint in CI never fails** — it reports and exits zero, so the pre-commit hook enforces it.
- **`make lint` differs from CI** — CI pins the linter's version and runs `go mod verify` first.

## Testing

**The shared contribution guide** defines the general approach to the testing in this codebase.

- **Decoder fixtures are datagrams** — each is built byte by byte, as a device lays it on the wire.
- **One skip is normal** — one test skips unless `XFLOW_TEST_ASN_DATABASE` names a MaxMind database.

## Documentation

The shared guide defines one owner per fact, and this table names the owner of each.

| Page                   | Owns                                                |
| :--------------------- | :-------------------------------------------------- |
| `README.md`            | What it is, how to run and scrape it                |
| `SECURITY.md`          | The exposure, the egress paths and redaction        |
| `docs/README.md`       | The index of the documentation                      |
| `docs/architecture.md` | The foundational architecture and design principles |
| `docs/collectors.md`   | The traffic metric catalogues and technical notes   |
| `docs/health.md`       | The health metric catalogues and technical notes    |
| `docs/enrichment.md`   | The operator's files, and the reload path           |
| `docs/help.md`         | The verbatim `--help` transcript                    |
| `docs/protocols.md`    | The wire formats and the verified devices           |
