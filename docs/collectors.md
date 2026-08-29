# Collectors

Every module is disabled by default and enabled per `--collector.<module>` flag. With none enabled the exporter receives, decodes and counts flows in the health series, and publishes no traffic series.

## Traffic Metrics

Each table family carries three metrics sharing one label set: `_bytes_total` and `_packets_total` are sampling-corrected counters, `_flows_total` counts flow records as exported. The `other` series of each family carries what the entry bound folded at ingest — see [Counter semantics](README.md#counter-semantics).

| Module          | Family prefix        | Labels                             |
| :-------------- | :------------------- | :--------------------------------- |
| `exporters`     | `xflow_exporter`     | `exporter,version`                 |
| `hosts`         | `xflow_host_pair`    | `exporter,src,dst`                 |
| `services`      | `xflow_service`      | `exporter,src,dst,proto,port`      |
| `destinations`  | `xflow_destination`  | `exporter,dst,proto,port`          |
| `tcp_flags`     | `xflow_tcp_flags`    | `exporter,flags`                   |
| `dscp`          | `xflow_dscp`         | `exporter,dscp`                    |
| `asns`          | `xflow_asn_pair`     | `exporter,src_asn,dst_asn`         |
| `applications`  | `xflow_application`  | `exporter,application`             |
| `countries`     | `xflow_country_pair` | `exporter,src_country,dst_country` |
| `threats`       | `xflow_threat`       | `exporter,address,direction`       |

### Label semantics

- `exporter` — the device's UDP source address, IPv4-mapped addresses unmapped.
- `port` — the destination port: the service side of the conversation as exported.
- `proto` — the conventional protocol name for the common IANA numbers, the number itself otherwise.
- `src_asn`/`dst_asn` — as exported, where `0` is a device that did not know the AS and no database placed the address. A record with neither AS feeds no entry. Where `--enrich.asn-database` is set, `xflow_asn_info{asn,organization}` names each AS the table holds, on its own series: a database respelling a company would otherwise break every counter it touches, and the table is Top-K bounded while a database names every AS there is. An AS no lookup resolved carries no name, which a join shows by finding nothing to join to.
- `application` — the device-announced AVC name, the inline vendor string, or the `engine:selector` split of `applicationId` when only the number is known. `--enrich.services` fills it from the transport port where none of those exist.
- `src_country`/`dst_country` — ISO codes from `--enrich.country-database`, `private` for an address on a LAN and `unknown` for a routable one the database could not place. Private means what Go's `netip` means by it, RFC 1918 and the IPv6 unique local range and nothing wider: shared address space, loopback and link-local have no country either but are not private, and naming them so would be the guess this distinction exists to avoid. A record neither side of which resolved feeds no entry.
- `address`/`direction` — a single address a threat list names and the side it was seen on. Only flagged addresses appear, so the table holds what is worth acting on rather than one entry per address seen.
- `flags` — the TCP control bits the flow's packets ORed together, rendered as names from the low bit up, the order `tcpdump` prints them in and the reverse of the header's own drawing, which is what Wireshark shows (`syn`, `syn,ack`, `fin,psh,ack`). Only TCP records feed it, and only those from a device that exported the field. A segment setting no bit is a NULL scan rather than a gap, so it keys `none` rather than being dropped.
- `dscp` — the top six bits of the TOS byte as the class they name, the number otherwise. The two bits dropped are ECN, which is congestion signaling rather than a class. A record built on `match ipv4 dscp` exports the code point alone as IE 195 instead of the byte, which reads the same here; the byte wins where a template carries both, carrying the ECN bits with it. Admission keys on whether the device reported either, not on the value: `cs0` is best-effort traffic and belongs in the table, while a device that exports neither feeds nothing.
- `destinations` is `services` without the source, so one entry reads as what a service received rather than who reached it. It is directional: an ingress-only pair of observation points keys the two directions of a conversation separately, so it is not a host total. Query-side folding of `services` matches it only while every source stays inside the Top-K cut, which a service reached by more sources than `--aggregation.top-k` does not.
- The `exporters` family publishes unfolded: its cardinality is the fleet's, which no Top-K needs to guard.

## Distributions

| Metric                        | Type             | Description                                     |
| :---------------------------- | :--------------- | :---------------------------------------------- |
| `xflow_flow_bytes`            | Native histogram | Sampling-corrected bytes per flow record        |
| `xflow_flow_duration_seconds` | Native histogram | Duration where the record carried both instants |

## Exporter Health Metrics

These series describe the exporter itself. They have no module flag.

| Metric                                              | Type    | Description                                          |
| :-------------------------------------------------- | :------ | :--------------------------------------------------- |
| `xflow_build_info`                                  | Gauge   | Exporter version in the `version` label, always 1    |
| `xflow_receiver_packets_total`                      | Counter | Datagrams read per `listener`, drops included        |
| `xflow_receiver_bytes_total`                        | Counter | Payload bytes received per `listener`                |
| `xflow_receiver_read_errors_total`                  | Counter | Socket read failures per `listener`                  |
| `xflow_receiver_dropped_packets_total`              | Counter | Pre-decode drops per `listener` and `reason`         |
| `xflow_receiver_queue_length`                       | Gauge   | Datagrams queued ahead of the decoders               |
| `xflow_receiver_queue_capacity`                     | Gauge   | Bound of that queue                                  |
| `xflow_flows_total`                                 | Counter | Records decoded per `exporter` and `version`         |
| `xflow_decode_errors_total`                         | Counter | Rejections per `exporter`, `version` and `reason`    |
| `xflow_last_flow_timestamp_seconds`                 | Gauge   | Unix time of the exporter's last decode              |
| `xflow_templates`                                   | Gauge   | Unexpired templates per domain and `type`            |
| `xflow_sequence_missed_total`                       | Counter | Export packets lost per domain                       |
| `xflow_sampling_rate`                               | Gauge   | Declared sampling rate, absent until one arrives     |
| `xflow_domains_refused_total`                       | Counter | Observation domains refused at the per-device budget |
| `xflow_vendor_strings_refused_total`                | Counter | Vendor strings refused as unrepresentable            |
| `xflow_applications_refused_total`                  | Counter | Announcements refused at the per-device app budget   |
| `xflow_exporters_refused_total`                     | Counter | Attributions refused at the process exporter budget  |
| `xflow_aggregation_entries`                         | Gauge   | Entries held per `aggregation` table                 |
| `xflow_aggregation_evictions_total`                 | Counter | Idle entries evicted per `aggregation`               |
| `xflow_aggregation_overflow_records_total`          | Counter | Records folded into `other` by the entry bound       |
| `xflow_enrichment_lookups_total`                    | Counter | Records per `enricher` and `result`                  |
| `xflow_threat_entries`                              | Gauge   | Flagged addresses held from the list files           |
| `xflow_threat_skipped_lines`                        | Gauge   | List lines that name no address, in the set in force |
| `xflow_threat_reloads_total`                        | Counter | List loads that succeeded, the initial one included  |
| `xflow_threat_reload_failures_total`                | Counter | List loads that failed, keeping the previous set     |
| `xflow_remote_write_sends_total`                    | Counter | Writes the remote endpoint accepted                  |
| `xflow_remote_write_failures_total`                 | Counter | Writes that failed                                   |
| `xflow_remote_write_samples_total`                  | Counter | Samples shipped, one per series per write            |
| `xflow_remote_write_last_success_timestamp_seconds` | Gauge   | Unix time of the last accepted write                 |

### Reason values

`xflow_decode_errors_total` carries one of a closed set of reasons:

| Reason                    | Meaning                                              |
| :------------------------ | :--------------------------------------------------- |
| `unsupported_version`     | A datagram no decoder claims                         |
| `malformed`               | A structure that does not fit its bytes              |
| `unsupported_aggregation` | A NetFlow v8 method outside the fourteen known       |
| `missing_template`        | A v9/IPFIX template that has not arrived yet         |
| `invalid_template`        | A template announcement the parser limits refuse     |
| `reserved_set`            | A flowset in the reserved 2-255 range                |
| `domain_limit`            | An observation domain past the device's budget       |

`xflow_receiver_dropped_packets_total` carries one of two:

| Reason       | Meaning                                              |
| :----------- | :--------------------------------------------------- |
| `queue_full` | A burst the queue could not absorb                   |
| `truncated`  | A datagram larger than `--receiver.max-packet-size`  |

**Freshness** — alert on `time() - xflow_last_flow_timestamp_seconds`: a silent device stops moving its timestamp while every counter freezes, and nothing else can tell that from a healthy quiet network.
