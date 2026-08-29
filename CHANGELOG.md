# Changelog

Notable changes to the metric surface, one section per release, listing the pull requests that release carries.

A minor release may rename or remove a metric. Every collector module flag is off by default, so a release that adds one adds no series until you set it.

## [Unreleased]

- [#10](https://github.com/umatare5/xflow-exporter/pull/10) — Release only on a VERSION change, and configure gitleaks

## [v0.7.0]

- [#9](https://github.com/umatare5/xflow-exporter/pull/9) — Serve metrics on the registered port 10053

## [v0.6.0]

- [#8](https://github.com/umatare5/xflow-exporter/pull/8) — Close the counting defects and rewrite the reference pages

## [v0.5.0]

- [#6](https://github.com/umatare5/xflow-exporter/pull/6) — Publish the remaining dimensions and bound the last wire map

## [v0.4.0]

- [#5](https://github.com/umatare5/xflow-exporter/pull/5) — Enrich records from local sources and ship them to remote write

## [v0.3.0]

- [#4](https://github.com/umatare5/xflow-exporter/pull/4) — Aggregate decoded records and publish them as series

## [v0.2.0]

- [#3](https://github.com/umatare5/xflow-exporter/pull/3) — Decode NetFlow v5/v8/v9, IPFIX and sFlow v5 into flow records

## [v0.1.0]

- [#1](https://github.com/umatare5/xflow-exporter/pull/1) — Start the exporter with its flags, HTTP surface and UDP receiver
- [#2](https://github.com/umatare5/xflow-exporter/pull/2) — Add the release workflow the tag and the artifacts come from

[Unreleased]: https://github.com/umatare5/xflow-exporter/compare/v0.7.0...HEAD
[v0.7.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.7.0
[v0.6.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.6.0
[v0.5.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.5.0
[v0.4.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.4.0
[v0.3.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.3.0
[v0.2.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.2.0
[v0.1.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.1.0
