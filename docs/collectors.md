# Collectors

This documentation provides an overview of the collectors supported by the xflow-exporter.

All collectors are **disabled by default.** Even with all collectors disabled, the exporter still receives and decodes flows.

## Metrics

The following table lists the metrics exposed by each collector, including their type and a brief description.

| Collector     | Metric                             | Type      | Description                |
| :------------ | :--------------------------------- | :-------- | :------------------------- |
| Exporters     | `xflow_exporter_bytes_total`       | Counter   | Sampling-corrected bytes   |
| Exporters     | `xflow_exporter_packets_total`     | Counter   | Sampling-corrected packets |
| Exporters     | `xflow_exporter_flows_total`       | Counter   | Flows the records reported |
| Hosts         | `xflow_interface_info`             | Gauge     | Always 1, naming a port    |
| Hosts         | `xflow_host_pair_bytes_total`      | Counter   | Sampling-corrected bytes   |
| Hosts         | `xflow_host_pair_packets_total`    | Counter   | Sampling-corrected packets |
| Hosts         | `xflow_host_pair_flows_total`      | Counter   | Flows the records reported |
| Services      | `xflow_service_bytes_total`        | Counter   | Sampling-corrected bytes   |
| Services      | `xflow_service_packets_total`      | Counter   | Sampling-corrected packets |
| Services      | `xflow_service_flows_total`        | Counter   | Flows the records reported |
| Destinations  | `xflow_destination_bytes_total`    | Counter   | Sampling-corrected bytes   |
| Destinations  | `xflow_destination_packets_total`  | Counter   | Sampling-corrected packets |
| Destinations  | `xflow_destination_flows_total`    | Counter   | Flows the records reported |
| TCP Flags     | `xflow_tcp_flags_bytes_total`      | Counter   | Sampling-corrected bytes   |
| TCP Flags     | `xflow_tcp_flags_packets_total`    | Counter   | Sampling-corrected packets |
| TCP Flags     | `xflow_tcp_flags_flows_total`      | Counter   | Flows the records reported |
| DSCP          | `xflow_dscp_bytes_total`           | Counter   | Sampling-corrected bytes   |
| DSCP          | `xflow_dscp_packets_total`         | Counter   | Sampling-corrected packets |
| DSCP          | `xflow_dscp_flows_total`           | Counter   | Flows the records reported |
| BGP AS        | `xflow_asn_pair_bytes_total`       | Counter   | Sampling-corrected bytes   |
| BGP AS        | `xflow_asn_pair_packets_total`     | Counter   | Sampling-corrected packets |
| BGP AS        | `xflow_asn_pair_flows_total`       | Counter   | Flows the records reported |
| BGP AS        | `xflow_asn_info`                   | Gauge     | Always 1, naming an AS     |
| Applications  | `xflow_application_bytes_total`    | Counter   | Sampling-corrected bytes   |
| Applications  | `xflow_application_packets_total`  | Counter   | Sampling-corrected packets |
| Applications  | `xflow_application_flows_total`    | Counter   | Flows the records reported |
| Countries     | `xflow_country_pair_bytes_total`   | Counter   | Sampling-corrected bytes   |
| Countries     | `xflow_country_pair_packets_total` | Counter   | Sampling-corrected packets |
| Countries     | `xflow_country_pair_flows_total`   | Counter   | Flows the records reported |
| Threats       | `xflow_threat_bytes_total`         | Counter   | Sampling-corrected bytes   |
| Threats       | `xflow_threat_packets_total`       | Counter   | Sampling-corrected packets |
| Threats       | `xflow_threat_flows_total`         | Counter   | Flows the records reported |
| VLANs         | `xflow_vlan_pair_bytes_total`      | Counter   | Sampling-corrected bytes   |
| VLANs         | `xflow_vlan_pair_packets_total`    | Counter   | Sampling-corrected packets |
| VLANs         | `xflow_vlan_pair_flows_total`      | Counter   | Flows the records reported |
| VLANs         | `xflow_vlan_info`                  | Gauge     | Always 1, naming a VLAN    |
| Distributions | `xflow_flow_bytes`                 | Histogram | Corrected bytes per record |
| Distributions | `xflow_flow_duration_seconds`      | Histogram | Flow duration in seconds   |
| All           | `xflow_device_info`                | Gauge     | Always 1, naming a device  |

> [!TIP]
>
> **BGP AS, Countries, VLANs, Threats, and the naming gauges** need the following enrichment files. See [Enrichment](../docs/enrichment.md) for more details.
>
> - `--enrich.asn-database`: MaxMind-format ASN database, filling the AS numbers a device omits
> - `--enrich.country-database`: MaxMind-format country database, filling the ISO codes for --collector.countries
> - `--enrich.mapping-file`: YAML file naming devices, their interfaces, VLANs and extra transport ports
> - `--enrich.services`: Name the application from the transport port where the device named none
> - `--enrich.threat-file`: File of flagged addresses, one per line (repeatable)
>
> The following two scripts help you to gather the necessary enrichment files:
>
> - [`scripts/fetch-enrichment-data.sh`](../scripts/fetch-enrichment-data.sh) — fetch the enrichment data for BGP AS, Countries and Threats.
> - [`scripts/fetch-device-names.sh`](../scripts/fetch-device-names.sh) — scrape the device information for Hosts, VLANs over SNMP and write out it.

## Labels

Every traffic family is labeled with `exporter_address` (except `xflow_asn_info`).

| Label                            | Value domain                                                            |
| :------------------------------- | :---------------------------------------------------------------------- |
| `exporter_address`               | UDP source address (IPv4-mapped IPv6 unmapped)                          |
| `version`                        | Export protocol (`netflow_v5`, `netflow_v9`, `ipfix`, `sflow_v5`, etc.) |
| `odid`                           | Observation Domain ID in decimal                                        |
| `src` / `dst`                    | Flow addresses                                                          |
| `proto`                          | Protocol name or number                                                 |
| `port`                           | Port a service table names, or the destination where neither does       |
| `side`                           | End the keyed value came from (`src`/`dst`)                             |
| `input_ifindex`/`output_ifindex` | SNMP ifIndex, or `0` if unknown                                         |
| `flags`                          | Cumulative TCP control bits (e.g., `syn,ack`), or `none`                |
| `dscp`                           | DSCP class name (e.g. `ef`), or the code point where none names it      |
| `src_asn`/`dst_asn`              | Exported or database-filled AS numbers, or `0` if unknown               |
| `asn`/`organization`             | AS number and database organization name                                |
| `application`                    | AVC name, vendor string, or `engine:selector`                           |
| `src_country`/`dst_country`      | ISO country code, `private`, or `unknown`                               |
| `address`                        | Flagged address                                                         |
| `direction`                      | Observation point (`ingress`, `egress`, `unknown`)                      |
| `src_vlan`/`dst_vlan`            | VLAN from mapping file, or `0` if unknown                               |
| `exporter_name`                  | Hostname from mapping file                                              |
| `ifindex`/`ifname`               | ifIndex and assigned name                                               |
| `vlan`/`vlan_name`               | VLAN ID and assigned name                                               |

## Annotations

**`xflow_*_total{…="other"}`**

Accumulates rejected ingest attempts bound by `--aggregation.max-entries`. The tail below Top-K and min-bytes cuts is withheld rather than folded to prevent breaking `rate()`. The `/entries` endpoint ranks every entry, and rows past its `published` count are that tail.

**`xflow_*_info`**

Publishing names as separate gauges avoids churning labels on metric counters when names are updated. `xflow_interface_info` and `xflow_asn_info` take the Top-K and min-bytes cuts, losing a name with its entry. The mapping file bounds `xflow_device_info` and `xflow_vlan_info`, so both publish regardless of traffic.

**`xflow_exporter_*`**

Takes no scrape-time Top-K or min-bytes cuts as its cardinality is bounded by the fleet, not traffic. Summing across `odid` counts traffic once per cache view rather than once overall. `_flows_total` counts one flow per record, except for v8 aggregates where it uses the cache's reported count.

**`xflow_host_pair_*`, `xflow_service_*`, `xflow_threat_*`**

The inclusion of interface pairs keeps asymmetrical paths distinct. Unrecorded paths are stored under `0`/`0`. Splitting one conversation across multiple paths increases cardinality and makes entries sparser.

**`xflow_destination_*`**

Unidirectional aggregate for destinations independent of sources. States total received volume per service. It is directional; the two directions of a conversation are keyed separately whichever points observed them. `side` says which end the `port` came from, a reply leg folding onto the service's port rather than taking an entry under a client's number.

**`xflow_tcp_flags_*`**

Fed only by TCP records from devices exporting the control-bit field. Templates omitting this field yield no entries rather than labeling them `none`.

**`xflow_dscp_*`**

Covers records from templates exporting either the TOS byte or code point.

**`xflow_asn_pair_*`**

Records with no AS on either side feed no entry. An unknown side opposite a known AS is labeled `0`.

**`xflow_country_pair_*`**

Records with unresolved countries on both sides feed no entry. Unresolved sides opposite a known country are labeled `unknown`.

**`xflow_threat_*`**

Only holds addresses flagged by a threat list. Records flagged on both sides open distinct entries for each.

**`xflow_vlan_pair_*`**

Records matching no mapping on either side feed no entry. A `0` indicates the opposite side is mapped. Requires `vlans` in `--enrich.mapping-file`.

**`xflow_flow_bytes`, `xflow_flow_duration_seconds`**

Native histograms observing flow byte sizes and durations, excluding unmeasured or clock-less records. Uses `NativeHistogramBucketFactor` of 1.1 (schema 3). Capped at 200 buckets per `exporter_address`, past which it resets whole where the last reset or creation is an hour or more old, zeroing `_count` and `_sum`, and otherwise halves resolution until then.

## Technical Notes

This section covers technical considerations and best practices for development, configuration, and operation.

**Interface Identifiers (`0`)**: `input_ifindex`/`output_ifindex` resolve to `0` when: the template omits IE 10 or 14; the device exported `0`; sFlow format 0 sets `0x3FFFFFFF` (agent is source/sink); sFlow format 1/2 indicate discard codes/counts; or the field width is unsupported by readers. RFC 2863 numbers interfaces from 1, preventing collision.

**Address Localization**: The `private` country designation is strictly bound to RFC 1918 and RFC 4193 unique local ranges. Shared address space, loopback, and link-local are not designated private, avoiding semantic guesswork.

**Exporter Behaviors**: `xflow_exporter_*` sums domains (e.g., NetFlow v8 methods, v9 Source IDs). Summing across `odid` counts traffic once per cache view. `_flows_total` relies on cache-reported counts for v8 aggregates, which differ from underlying flows.

**Measured Counts**: `_bytes_total` and `_packets_total` appear only for entries every record of which carried that count. A device keeping its counters in elements this decoder does not read leaves the family absent rather than zero, permanently for that entry, while `_flows_total` is published throughout. Such an entry ranks last, both cuts being by byte volume, so Top-K or `--aggregation.min-bytes` withholds it whole, the packet count it did measure included. The `other` fold is exempt, being a lower bound already. The `bytes_measured` and `packets_measured` fields of `/entries` say which entries are affected.

**Observation Points**: `direction` carries IE 61 on v9 and IPFIX, and is derived on sFlow. It separates the two readings a device gives for a path it watches at both ends without correcting their sum, so summing across the label returns the doubled figure and selecting one direction the measured one. The two flow distributions carry no such label and double the same way.

**Application Names**: The table a device announces through its options expires on `--parser.template-ttl`, so a device whose application-table timer is longer than that loses its names between announcements. The `application` label then falls back to `engine:selector`, splitting one application across two series until the device announces again.

**Cardinality Impact**: Splitting conversations across multiple asymmetrical paths (via interface pairs) increases entries by `1 + share × (k−1)`, where `k` is the interface pair count. This sparsity can cause entries to idle, face eviction, and under-report rates upon reappearance.

**Histogram Export**: Native histograms for flow sizes and durations maintain bucket fidelity (`NativeHistogramBucketFactor` of 1.1) and are exposed whole when `scrape_native_histograms` is enabled. Without it, negotiation falls back to text exposition containing only `_count`, `_sum`, and one `+Inf` bucket.
