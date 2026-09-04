# Collectors

Every module is disabled by default and enabled per `--collector.<module>` flag, underscores in the name spelled as hyphens: `tcp_flags` takes `--collector.tcp-flags`. With none enabled the exporter still receives, decodes and counts flows in the [health series](health.md), and publishes no traffic series.

## Metrics

| Module         | Metric                             | Type    | Description                     |
| :------------- | :--------------------------------- | :------ | :------------------------------ |
| `exporters`    | `xflow_exporter_bytes_total`       | Counter | Sampling-corrected bytes        |
| `exporters`    | `xflow_exporter_packets_total`     | Counter | Sampling-corrected packets      |
| `exporters`    | `xflow_exporter_flows_total`       | Counter | Flow records as exported        |
| `hosts`        | `xflow_host_pair_bytes_total`      | Counter | Sampling-corrected bytes        |
| `hosts`        | `xflow_host_pair_packets_total`    | Counter | Sampling-corrected packets      |
| `hosts`        | `xflow_host_pair_flows_total`      | Counter | Flow records as exported        |
| `services`     | `xflow_service_bytes_total`        | Counter | Sampling-corrected bytes        |
| `services`     | `xflow_service_packets_total`      | Counter | Sampling-corrected packets      |
| `services`     | `xflow_service_flows_total`        | Counter | Flow records as exported        |
| `destinations` | `xflow_destination_bytes_total`    | Counter | Sampling-corrected bytes        |
| `destinations` | `xflow_destination_packets_total`  | Counter | Sampling-corrected packets      |
| `destinations` | `xflow_destination_flows_total`    | Counter | Flow records as exported        |
| `tcp_flags`    | `xflow_tcp_flags_bytes_total`      | Counter | Sampling-corrected bytes        |
| `tcp_flags`    | `xflow_tcp_flags_packets_total`    | Counter | Sampling-corrected packets      |
| `tcp_flags`    | `xflow_tcp_flags_flows_total`      | Counter | Flow records as exported        |
| `dscp`         | `xflow_dscp_bytes_total`           | Counter | Sampling-corrected bytes        |
| `dscp`         | `xflow_dscp_packets_total`         | Counter | Sampling-corrected packets      |
| `dscp`         | `xflow_dscp_flows_total`           | Counter | Flow records as exported        |
| `asns`         | `xflow_asn_pair_bytes_total`       | Counter | Sampling-corrected bytes        |
| `asns`         | `xflow_asn_pair_packets_total`     | Counter | Sampling-corrected packets      |
| `asns`         | `xflow_asn_pair_flows_total`       | Counter | Flow records as exported        |
| `asns`         | `xflow_asn_info`                   | Gauge   | Always 1, naming a published AS |
| `applications` | `xflow_application_bytes_total`    | Counter | Sampling-corrected bytes        |
| `applications` | `xflow_application_packets_total`  | Counter | Sampling-corrected packets      |
| `applications` | `xflow_application_flows_total`    | Counter | Flow records as exported        |
| `countries`    | `xflow_country_pair_bytes_total`   | Counter | Sampling-corrected bytes        |
| `countries`    | `xflow_country_pair_packets_total` | Counter | Sampling-corrected packets      |
| `countries`    | `xflow_country_pair_flows_total`   | Counter | Flow records as exported        |
| `threats`      | `xflow_threat_bytes_total`         | Counter | Sampling-corrected bytes        |
| `threats`      | `xflow_threat_packets_total`       | Counter | Sampling-corrected packets      |
| `threats`      | `xflow_threat_flows_total`         | Counter | Flow records as exported        |

## Labels

Every family carries `exporter_address`, and the labels beside it are its aggregation key, so two records sharing that set share one entry.

| Label                            | Description                                                      |
| :------------------------------- | :--------------------------------------------------------------- |
| `exporter_address`               | The device's UDP source address, IPv4-mapped addresses unmapped  |
| `version`                        | The protocol a record arrived in, on `exporters` alone           |
| `src`/`dst`                      | The flow's addresses, the destination alone on `destinations`    |
| `proto`                          | The conventional protocol name, the number where unnamed         |
| `port`                           | The destination port, the service side of the conversation       |
| `input_ifindex`/`output_ifindex` | The interfaces the flow crossed, `0` where the export named none |
| `flags`                          | The TCP control bits ORed together, named from the low bit up    |
| `dscp`                           | The top six bits of the TOS byte as the class they name          |
| `src_asn`/`dst_asn`              | The AS numbers as exported, `0` where none was known             |
| `asn`/`organization`             | One AS number and its database name, on `xflow_asn_info`         |
| `application`                    | The AVC name, the inline vendor string, or `engine:selector`     |
| `src_country`/`dst_country`      | ISO codes, `private` on a LAN, `unknown` where unplaced          |
| `address`/`direction`            | A flagged address and the side of the flow it was seen on        |

**`version`**

NetFlow-Lite is NetFlow v9 on the wire and reads `netflow_v9`, the packet section it carries being a record shape rather than a version of its own.

**`flags`**

Rendered as `syn`, `syn,ack` or `fin,psh,ack`, and a segment setting no bit is a NULL scan rather than a gap, so it keys `none` rather than being dropped.

**`dscp`**

A record built on `match ipv4 dscp` exports the code point alone as IE 195 instead of the byte, which reads the same here; the byte wins where a template carries both, carrying the ECN bits with it.

**`input_ifindex`/`output_ifindex`**

The interfaces the flow crossed, on `hosts`, `services` and `threats`. RFC 2863 numbers an interface from 1, so `0` is an interface the export did not name and cannot collide with a real port.

| Cause of a `0`                              | What the device meant                     |
| :------------------------------------------ | :---------------------------------------- |
| The template omits IE 10 or IE 14           | It reports no interface at all            |
| The device exported `0`                     | It reports the interface as unknown       |
| sFlow format 0, value `0x3FFFFFFF`          | The agent itself is the source or sink    |
| sFlow format 1 or 2                         | A discard code or a destination count     |
| IE 10 or IE 14 exported three octets wide   | Nothing — the field width has no reader   |
| IE 10 or IE 14 exported wider than `uint32` | Nothing — the narrowing reader refuses it |

The six are indistinguishable once published. NetFlow v8's one-sided aggregations carry a single address, so they reach neither `hosts` nor `services` and their `0` appears on `threats` alone.

**`src_asn`/`dst_asn`**

`0` means the device did not know the AS and no database placed the address, so it is a reading rather than an unset label.

**`application`**

The `engine:selector` split is what a record carrying only the numbered `applicationId` resolves to, and `--enrich.services` fills the label from the transport port where none of the three exist.

**`src_country`/`dst_country`**

Private means what Go's `netip` means by it, RFC 1918 and the IPv6 unique local range and nothing wider: shared address space, loopback and link-local have no country either but are not private, and naming them so would be the guess this distinction exists to avoid.

- `unknown` is a side the database holds no country for, or no address at all on that side.

## Specifications

Each entry carries what the series' HELP text and the shared [Absence](README.md#absence) rules do not.

**the `other` series of every family**

every label reads `other`, and the series carries what the aggregation's entry bound rejected at ingest and nothing else, so a family stays whole across the point where `--aggregation.max-entries` stopped it opening a new entry.

- The tail below the Top-K and min-bytes cuts is withheld rather than summed into it — [Counter semantics](README.md#counter-semantics) carries why folding that tail, or an evicted entry's totals, would break `rate()`.
- `input_ifindex` and `output_ifindex` read `other` on it too, so the fold row of those three families joins to no interface and its bytes stay unattributed to a port.

**the three `xflow_exporter_*` counters**

the per-device family takes no scrape-time cut, neither Top-K nor min-bytes, because its cardinality is the fleet's rather than the traffic's — a device that exported one small flow keeps its own series where the same volume in another family could fall outside the Top-K or below `--aggregation.min-bytes` and publish nothing.

**the interface pair on `hosts`, `services` and `threats`**

it keys those three tables, so one address pair reached over two paths reads as two entries rather than one sum no path can be read out of. A record naming neither interface still opens an entry under `0`/`0`, because dropping it would lose the traffic and not just its path.

- The other seven families do not carry it. Each already folds many conversations into one row, and multiplying that row by every path its members crossed turns a per-device ratio into a per-path one with nothing in the labels saying so.
- Entries multiply by `1 + share × (k−1)`, `k` being the interface pairs one conversation spreads over and `share` the fraction that spread at all. The bound is the input interface count times the output one; `xflow_aggregation_entries` and `xflow_aggregation_overflow_records_total` are what it costs in practice.
- Splitting one conversation across paths makes each entry sparser, and an entry that idles past `--aggregation.entry-ttl` is evicted and reopened. `rate()` extrapolates only half an interval back to a reappearing series' first sample, so the folded-back sum reads low.
- NetFlow v5 and v8 size the interface fields at two octets, so an ifIndex above 65535 has no spelling there and what a device sends in its place is the device's own choice.
- The device has to number its interfaces persistently across reloads. Where it does not, a reboot or a card swap renumbers the ports and nothing in the export says the numbering moved.

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
