# Changelog

Notable changes to the metric surface, one section per release, listing the pull requests that release carries.

## [Unreleased]

## [v0.13.1]

- [#105](https://github.com/umatare5/xflow-exporter/pull/105) — Rebuild on every make build and keep worktrees on make clean
- [#106](https://github.com/umatare5/xflow-exporter/pull/106) — Prune a full domain only once a template can expire
- [#108](https://github.com/umatare5/xflow-exporter/pull/108) — Write American English across the docs, comments and dashboard
- [#109](https://github.com/umatare5/xflow-exporter/pull/109) — Render the coverage badge in CI instead of committing it

## [v0.13.0]

- [#90](https://github.com/umatare5/xflow-exporter/pull/90) — Align the documentation set with cisco-wnc-exporter
- [#91](https://github.com/umatare5/xflow-exporter/pull/91) — Close the remaining gaps against cisco-wnc-exporter
- [#92](https://github.com/umatare5/xflow-exporter/pull/92) — Consolidate markdownlint-cli2.jsonc comment
- [#93](https://github.com/umatare5/xflow-exporter/pull/93) — Scope templates by transport session
- [#94](https://github.com/umatare5/xflow-exporter/pull/94) — Free the expired templates of live domains in the sweep
- [#95](https://github.com/umatare5/xflow-exporter/pull/95) — Bound the template fields one device holds
- [#96](https://github.com/umatare5/xflow-exporter/pull/96) — Apply a scoped sampling rate only to what it names
- [#97](https://github.com/umatare5/xflow-exporter/pull/97) — State the RFC deviations and correct the audited claims
- [#98](https://github.com/umatare5/xflow-exporter/pull/98) — Log the template elements no reader consumes
- [#99](https://github.com/umatare5/xflow-exporter/pull/99) — Discard a malformed IPFIX message whole
- [#100](https://github.com/umatare5/xflow-exporter/pull/100) — Read applicationId as RFC 6759 lays it out
- [#101](https://github.com/umatare5/xflow-exporter/pull/101) — Take an absolute flow clock only as a whole pair
- [#102](https://github.com/umatare5/xflow-exporter/pull/102) — Withdraw a refused template and read past it
- [#103](https://github.com/umatare5/xflow-exporter/pull/103) — Replace a counter only when the record omits it

## [v0.12.0]

- [#67](https://github.com/umatare5/xflow-exporter/pull/67) — Narrow the collector table so no cell wraps on GitHub
- [#68](https://github.com/umatare5/xflow-exporter/pull/68) — Update README.md
- [#71](https://github.com/umatare5/xflow-exporter/pull/71) — List every entry an aggregation table holds behind a flag
- [#72](https://github.com/umatare5/xflow-exporter/pull/72) — Hold the metric pages to what the collectors publish
- [#73](https://github.com/umatare5/xflow-exporter/pull/73) — Bound flow histogram series and the range one series holds
- [#74](https://github.com/umatare5/xflow-exporter/pull/74) — Count the records no sampling declaration settles a rate for
- [#75](https://github.com/umatare5/xflow-exporter/pull/75) — Bound the devices holding domain state
- [#76](https://github.com/umatare5/xflow-exporter/pull/76) — Hold each wire element to the width and count its spec defines
- [#77](https://github.com/umatare5/xflow-exporter/pull/77) — Measure each flow clock back from the export or withhold it
- [#78](https://github.com/umatare5/xflow-exporter/pull/78) — Redact the endpoint, bound the writes, and cut the scrape work
- [#79](https://github.com/umatare5/xflow-exporter/pull/79) — Number each transport session's export sequence apart
- [#80](https://github.com/umatare5/xflow-exporter/pull/80) — Restore the absence rule and move the credential out of the URL
- [#81](https://github.com/umatare5/xflow-exporter/pull/81) — Settle each sampling rate against the declaration that names it
- [#82](https://github.com/umatare5/xflow-exporter/pull/82) — Route an aggregate by the fold its own template declares
- [#83](https://github.com/umatare5/xflow-exporter/pull/83) — Key every traffic family on the observation point it was taken at
- [#84](https://github.com/umatare5/xflow-exporter/pull/84) — Key the service families on the port a service table names
- [#85](https://github.com/umatare5/xflow-exporter/pull/85) — Withhold the counted family no device measured
- [#86](https://github.com/umatare5/xflow-exporter/pull/86) — Name the end of a flow the way RFC 5103 names it
- [#87](https://github.com/umatare5/xflow-exporter/pull/87) — Stop a retry from holding the test stub server open

## [v0.11.0]

- [#64](https://github.com/umatare5/xflow-exporter/pull/64) — Describe what each series counts and what the sampling audit returns
- [#65](https://github.com/umatare5/xflow-exporter/pull/65) — Break traffic down by the VLAN a mapping file puts each address on
- [#66](https://github.com/umatare5/xflow-exporter/pull/66) — Restructure the documentation set and repair its cross-links

## [v0.10.0]

- [#47](https://github.com/umatare5/xflow-exporter/pull/47) — Split the docs by owner, rename the collector, and fix the rendering
- [#48](https://github.com/umatare5/xflow-exporter/pull/48) — Gather the contributor conventions and cut them to reading length
- [#49](https://github.com/umatare5/xflow-exporter/pull/49) — Ship only the licenses and the parsed config beside the binary
- [#50](https://github.com/umatare5/xflow-exporter/pull/50) — Point the contributor pages at the shared baseline
- [#52](https://github.com/umatare5/xflow-exporter/pull/52) — Clamp the sampling correction and refuse an overlong sampled packet
- [#53](https://github.com/umatare5/xflow-exporter/pull/53) — Stamp the freshness instant on a record and publish the datagram instant
- [#54](https://github.com/umatare5/xflow-exporter/pull/54) — Publish what an sFlow agent sampled and could not send
- [#55](https://github.com/umatare5/xflow-exporter/pull/55) — Record the sFlow device the decoder was read against
- [#56](https://github.com/umatare5/xflow-exporter/pull/56) — Drop the device this decoder never read from the verified table
- [#57](https://github.com/umatare5/xflow-exporter/pull/57) — Correct a sampled record by the sampler it names
- [#58](https://github.com/umatare5/xflow-exporter/pull/58) — Key a device's traffic on the observation domain that reported it
- [#59](https://github.com/umatare5/xflow-exporter/pull/59) — Track the NetFlow v5 and v8 export sequence, and part the two flow counters
- [#60](https://github.com/umatare5/xflow-exporter/pull/60) — Note the Juniper devices the protocol table plans to verify
- [#61](https://github.com/umatare5/xflow-exporter/pull/61) — Name the flow count a v9 aggregation cache does declare
- [#62](https://github.com/umatare5/xflow-exporter/pull/62) — Record the v5 sampler a device names without its rate

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

[Unreleased]: https://github.com/umatare5/xflow-exporter/compare/v0.13.1...HEAD
[v0.13.1]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.13.1
[v0.13.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.13.0
[v0.12.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.12.0
[v0.11.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.11.0
[v0.10.0]: https://github.com/umatare5/xflow-exporter/releases/tag/v0.10.0
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
