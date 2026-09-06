# Contributing

The [shared conventions](https://github.com/umatare5/.github/blob/main/CONTRIBUTING.md) carry the tool setup, the `make` targets, the hook order, the release procedure and the pull request rules. This page carries what is specific to this exporter.

## Development

CI runs Format and Lint, Test and Build, Coverage against a threshold of 80 percent, Prometheus Rules, markdownlint, Link Check, actionlint, CodeQL and govulncheck on every pull request.

## Testing

- **Fixtures are datagrams** — each is laid out as a device lays it out, and its addresses come from the RFC 5737 documentation ranges or RFC 1918, never from a monitored network or a real device.
- **One skip is normal** — a test skips unless `XFLOW_TEST_ASN_DATABASE` names a MaxMind database.

Three commands reproduce the `Prometheus Rules` job locally.

```bash
promtool check rules --lint all --lint-fatal examples/prometheus_*_rules.yml
promtool test rules examples/prometheus_*_rules_test.yml
promtool check config --lint all --lint-fatal examples/prometheus.yml
```

## Code Style

A `--collector.<name>` flag switches a collector, a named series group is a family, and a table is the aggregation mechanism behind a collector.

A HELP string states the reading of one series in one sentence, and a family that folds at the entry bound says so in it, as in `Sampling-corrected bytes per exporter and version, other carries the entry-bound fold`.

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

A sentence about what a device exports is written only after that device's own export was decoded, and the `Verified on` column in `docs/protocols.md` names which device each claim came from.
