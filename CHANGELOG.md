# Changelog

Notable changes to the metric surface, one section per release, listing the pull requests that release carries.

## [Unreleased]

- [#47](https://github.com/umatare5/xflow-exporter/pull/47) — Split the docs by owner, rename the collector, and fix the rendering
- [#48](https://github.com/umatare5/xflow-exporter/pull/48) — Gather the contributor conventions and cut them to reading length
- [#49](https://github.com/umatare5/xflow-exporter/pull/49) — Ship only the licences and the parsed config beside the binary

## [v0.9.1]

- [#40](https://github.com/umatare5/xflow-exporter/pull/40) — Pin the counter, threat and interface guards nine surviving mutations found unheld
- [#41](https://github.com/umatare5/xflow-exporter/pull/41) — Stop the SNMP walk writing a mapping file the exporter refuses
- [#42](https://github.com/umatare5/xflow-exporter/pull/42) — Fail `--dry-run` on the enrichment files only a real startup opened
- [#43](https://github.com/umatare5/xflow-exporter/pull/43) — Record what a dry run now opens and what it still does not check

## [v0.9.0]

- [#21](https://github.com/umatare5/xflow-exporter/pull/21) — Add the govulncheck badge to the README
- [#22](https://github.com/umatare5/xflow-exporter/pull/22) — Give each overview point something only it says
- [#23](https://github.com/umatare5/xflow-exporter/pull/23) — Hold the architecture diagram to the line it illustrates
- [#24](https://github.com/umatare5/xflow-exporter/pull/24) — Update dependency golangci/golangci-lint to v2.13.2
- [#25](https://github.com/umatare5/xflow-exporter/pull/25) — Rename exporter to exporter_address, add the interface pair and the naming series
- [#26](https://github.com/umatare5/xflow-exporter/pull/26) — Update umatare5/common action to v0.18.0
- [#27](https://github.com/umatare5/xflow-exporter/pull/27) — Record the verified devices, separate NetFlow v9 from IPFIX, and document packet sections by their own name
- [#28](https://github.com/umatare5/xflow-exporter/pull/28) — Rename docs/configuration.md to docs/help.md
- [#29](https://github.com/umatare5/xflow-exporter/pull/29) — Withhold the size histogram where the record carried no byte count
- [#30](https://github.com/umatare5/xflow-exporter/pull/30) — Decode each device's datagrams in wire order, which reordering had counted as sequence loss
- [#33](https://github.com/umatare5/xflow-exporter/pull/33) — Receive flows on the registered port 4739 rather than the conventional 2055
- [#34](https://github.com/umatare5/xflow-exporter/pull/34) — Unify the security policy sections and restate the domain rules as claims
- [#35](https://github.com/umatare5/xflow-exporter/pull/35) — Name only the protocols a traffic breakdown reads, leaving the rest to a mapping file
- [#37](https://github.com/umatare5/xflow-exporter/pull/37) — Alert on a listener that receives nothing, and correct what the verified devices export

## [v0.8.0]

- [#10](https://github.com/umatare5/xflow-exporter/pull/10) — Release only on a VERSION change, and configure gitleaks
- [#11](https://github.com/umatare5/xflow-exporter/pull/11) — Add badges, an architecture diagram and the Grafana dashboard update
- [#12](https://github.com/umatare5/xflow-exporter/pull/12) — Add lychee link check configuration
- [#13](https://github.com/umatare5/xflow-exporter/pull/13) — Tighten markdownlint rules and pin the hook
- [#14](https://github.com/umatare5/xflow-exporter/pull/14) — Add the markdownlint workflow
- [#15](https://github.com/umatare5/xflow-exporter/pull/15) — Record the pre-commit and link check tooling
- [#16](https://github.com/umatare5/xflow-exporter/pull/16) — Set file path links in code style
- [#17](https://github.com/umatare5/xflow-exporter/pull/17) — Add a Prometheus recording rules example
- [#18](https://github.com/umatare5/xflow-exporter/pull/18) — Guard the branch and lint workflows locally
- [#19](https://github.com/umatare5/xflow-exporter/pull/19) — Refresh the service port table for current networks

## [v0.7.0]

- [#9](https://github.com/umatare5/xflow-exporter/pull/9) — Serve metrics on the registered port 10053
- [#7](https://github.com/umatare5/xflow-exporter/pull/7) — Update dependency prometheus/prometheus to v3.14.0

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

[Unreleased]: https://github.com/umatare5/xflow-exporter/compare/v0.9.1...HEAD
[v0.9.1]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.9.1
[v0.9.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.9.0
[v0.8.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.8.0
[v0.7.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.7.0
[v0.6.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.6.0
[v0.5.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.5.0
[v0.4.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.4.0
[v0.3.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.3.0
[v0.2.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.2.0
[v0.1.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.1.0
