# Collectors

Every module is disabled by default and enabled per `--collector.<module>` flag, underscores in the name spelled as hyphens: `tcp_flags` takes `--collector.tcp-flags`. With none enabled the exporter still receives, decodes and counts flows in the [health series](../README.md#exporter-health-metrics), and publishes no traffic series.

## Metrics

| Module         | Metric                             | Type    | Description                                         |
| :------------- | :--------------------------------- | :------ | :-------------------------------------------------- |
| `exporters`    | `xflow_exporter_bytes_total`       | Counter | Sampling-corrected bytes per exporter and version   |
| `exporters`    | `xflow_exporter_packets_total`     | Counter | Sampling-corrected packets per exporter and version |
| `exporters`    | `xflow_exporter_flows_total`       | Counter | Flow records as exported per exporter and version   |
| `hosts`        | `xflow_host_pair_bytes_total`      | Counter | Sampling-corrected bytes per address pair           |
| `hosts`        | `xflow_host_pair_packets_total`    | Counter | Sampling-corrected packets per address pair         |
| `hosts`        | `xflow_host_pair_flows_total`      | Counter | Flow records as exported per address pair           |
| `services`     | `xflow_service_bytes_total`        | Counter | Sampling-corrected bytes per service five-tuple     |
| `services`     | `xflow_service_packets_total`      | Counter | Sampling-corrected packets per service five-tuple   |
| `services`     | `xflow_service_flows_total`        | Counter | Flow records as exported per service five-tuple     |
| `destinations` | `xflow_destination_bytes_total`    | Counter | Sampling-corrected bytes per destination service    |
| `destinations` | `xflow_destination_packets_total`  | Counter | Sampling-corrected packets per destination service  |
| `destinations` | `xflow_destination_flows_total`    | Counter | Flow records as exported per destination service    |
| `tcp_flags`    | `xflow_tcp_flags_bytes_total`      | Counter | Sampling-corrected bytes per control-bit profile    |
| `tcp_flags`    | `xflow_tcp_flags_packets_total`    | Counter | Sampling-corrected packets per control-bit profile  |
| `tcp_flags`    | `xflow_tcp_flags_flows_total`      | Counter | Flow records as exported per control-bit profile    |
| `dscp`         | `xflow_dscp_bytes_total`           | Counter | Sampling-corrected bytes per DSCP class             |
| `dscp`         | `xflow_dscp_packets_total`         | Counter | Sampling-corrected packets per DSCP class           |
| `dscp`         | `xflow_dscp_flows_total`           | Counter | Flow records as exported per DSCP class             |
| `asns`         | `xflow_asn_pair_bytes_total`       | Counter | Sampling-corrected bytes per AS pair                |
| `asns`         | `xflow_asn_pair_packets_total`     | Counter | Sampling-corrected packets per AS pair              |
| `asns`         | `xflow_asn_pair_flows_total`       | Counter | Flow records as exported per AS pair                |
| `asns`         | `xflow_asn_info`                   | Gauge   | Always 1, naming an AS a published pair carries     |
| `applications` | `xflow_application_bytes_total`    | Counter | Sampling-corrected bytes per application            |
| `applications` | `xflow_application_packets_total`  | Counter | Sampling-corrected packets per application          |
| `applications` | `xflow_application_flows_total`    | Counter | Flow records as exported per application            |
| `countries`    | `xflow_country_pair_bytes_total`   | Counter | Sampling-corrected bytes per country pair           |
| `countries`    | `xflow_country_pair_packets_total` | Counter | Sampling-corrected packets per country pair         |
| `countries`    | `xflow_country_pair_flows_total`   | Counter | Flow records as exported per country pair           |
| `threats`      | `xflow_threat_bytes_total`         | Counter | Sampling-corrected bytes per flagged address        |
| `threats`      | `xflow_threat_packets_total`       | Counter | Sampling-corrected packets per flagged address      |
| `threats`      | `xflow_threat_flows_total`         | Counter | Flow records as exported per flagged address        |

## Labels

Every family carries `exporter`, and the labels beside it name the dimension its module aggregates on. That set is the table's key, so two records sharing it share one entry.

**`exporter`**

the device's UDP source address, IPv4-mapped addresses unmapped.

**`version`**

the protocol a record arrived in, carried by the `exporters` family alone: `netflow_v5`, `netflow_v8`, `netflow_v9`, `ipfix` or `sflow_v5`.

- NetFlow-Lite is NetFlow v9 on the wire and reads `netflow_v9`, the packet section it carries being a record shape rather than a version of its own.

**`src`/`dst`**

the flow's addresses as the device exported them, `hosts` and `services` carrying both while `destinations` carries the destination alone.

**`proto`**

the conventional protocol name for the common IANA numbers, the number itself otherwise, on `services` and `destinations` alike.

**`port`**

the destination port: the service side of the conversation as exported.

**`flags`**

the TCP control bits the flow's packets ORed together, rendered as names from the low bit up (`syn`, `syn,ack`, `fin,psh,ack`).

- A segment setting no bit is a NULL scan rather than a gap, so it keys `none` rather than being dropped.

**`dscp`**

the top six bits of the TOS byte as the class they name, the number otherwise.

- A record built on `match ipv4 dscp` exports the code point alone as IE 195 instead of the byte, which reads the same here; the byte wins where a template carries both, carrying the ECN bits with it.

**`src_asn`/`dst_asn`**

the AS numbers as exported, where `0` is a device that did not know the AS and no database placed the address.

**`asn`/`organization`**

one AS number and what `--enrich.asn-database` calls it, carried by `xflow_asn_info` alone.

**`application`**

the device-announced AVC name, the inline vendor string, or the `engine:selector` split of `applicationId` when only the number is known.

- `--enrich.services` fills it from the transport port where none of those exist.

**`src_country`/`dst_country`**

ISO codes from `--enrich.country-database`, `private` for an address on a LAN and `unknown` for a side it could not place — an address the database holds no country for, or no address at all on that side.

- Private means what Go's `netip` means by it, RFC 1918 and the IPv6 unique local range and nothing wider: shared address space, loopback and link-local have no country either but are not private, and naming them so would be the guess this distinction exists to avoid.

**`address`/`direction`**

a single address a threat list names, and the side of the flow it was seen on, `src` or `dst`.

## Specifications

Each entry carries what the series' HELP text and the shared [Absence](README.md#absence) rules do not.

**the `other` series of every family**

every label reads `other`, and the series carries what the aggregation's entry bound rejected at ingest and nothing else, so a family stays whole across the point where `--aggregation.max-entries` stopped it opening a new entry.

- The tail below the Top-K and min-bytes cuts is withheld rather than summed into it — [Counter semantics](README.md#counter-semantics) carries why folding that tail, or an evicted entry's totals, would break `rate()`.

**the three `xflow_exporter_*` counters**

the per-device family takes no scrape-time cut, neither Top-K nor min-bytes, because its cardinality is the fleet's rather than the traffic's — a device that exported one small flow keeps its own series where the same volume in another family could fall outside the Top-K or below `--aggregation.min-bytes` and publish nothing.

**the three `xflow_destination_*` counters**

`destinations` is `services` without the source, so one entry reads as what a service received in total rather than what any one client sent it, and a record whose source never resolved still names the service it reached.

- It is directional: an ingress-only pair of observation points keys the two directions of a conversation separately, so it is not a host total.
- Folding `xflow_service_*` in a query matches it only while every source stays inside the Top-K cut, which a service reached by more sources than `--aggregation.top-k` does not.

**the three `xflow_tcp_flags_*` counters**

only TCP records feed them, and only those from a device that exported the control-bit field, so a template omitting the field leaves the module with no entry at all rather than a table in which every profile reads `none`.

**the three `xflow_dscp_*` counters**

admission keys on whether the device reported the TOS byte or the code point at all, not on the value either carried, so the table covers every record whose template named one of the two and no record besides.

- `cs0` is best-effort traffic rather than an unset field, which is the distinction an admission test on the value would lose.

**the three `xflow_asn_pair_*` counters**

a record neither side of which carries an AS feeds no entry, while one side alone opens one and the unknown side reads `0`, so a `0` in the table always sits opposite an AS that was known.

**`xflow_asn_info`**

it names each AS the published pairs carry, and the name rides its own series rather than the counters' labels because a database respelling a company would otherwise break every counter it touches.

- It follows the same cut those pairs take, the table behind that cut running to `--aggregation.max-entries` while a database names every AS there is.
- An AS no lookup resolved carries no name, which a join shows by finding nothing to join to, and the series is absent altogether without `--enrich.asn-database`.

**the three `xflow_country_pair_*` counters**

a record neither side of which resolved feeds no entry, while one side alone opens one and the other reads `unknown`, so a pair of empty codes never reaches the table as a place of its own.

**the three `xflow_threat_*` counters**

only addresses a list flags appear, so the table holds what is worth acting on rather than one entry per address seen, and a record flagged on both sides opens an entry for each of them.
