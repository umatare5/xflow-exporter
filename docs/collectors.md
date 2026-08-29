# Collectors

Every module is disabled by default and enabled per `--collector.<module>` flag. With none enabled the exporter receives, decodes and counts flows in the health series, and publishes no traffic series.

## Traffic Metrics

Each table family carries three metrics sharing one label set: `_bytes_total` and `_packets_total` are sampling-corrected counters, `_flows_total` counts flow records as exported. The `other` series of each family folds the tail — see [Counter semantics](README.md#counter-semantics).

| Module         | Family prefix        | Labels                             |
| :------------- | :------------------- | :--------------------------------- |
| `exporters`    | `xflow_exporter`     | `exporter,version`                 |
| `hosts`        | `xflow_host_pair`    | `exporter,src,dst`                 |
| `services`     | `xflow_service`      | `exporter,src,dst,proto,port`      |
| `asns`         | `xflow_asn_pair`     | `exporter,src_asn,dst_asn`         |
| `applications` | `xflow_application`  | `exporter,application`             |
| `countries`    | `xflow_country_pair` | `exporter,src_country,dst_country` |
| `threats`      | `xflow_threat`       | `exporter,address,direction`       |

### Label semantics

- `exporter` — the device's UDP source address, IPv4-mapped addresses unmapped.
- `port` — the destination port: the service side of the conversation as exported.
- `proto` — the conventional protocol name for the common IANA numbers, the number itself otherwise.
- `src_asn`/`dst_asn` — as exported, where `0` is a device that did not know the AS. A record with neither AS feeds no entry.
- `application` — the device-announced AVC name, the inline vendor string, or the `engine:selector` split of `applicationId` when only the number is known. `--enrich.services` fills it from the transport port where none of those exist.
- `src_country`/`dst_country` — ISO codes from `--enrich.country-database`, `unknown` for a side the database could not place. A record neither side of which resolved feeds no entry.
- `address`/`direction` — a single address a reputation source flagged and the side it was seen on. Only flagged addresses appear, so the table holds what is worth acting on rather than one entry per address seen.
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
| `xflow_receiver_packets_total`                      | Counter | Datagrams received per `listener`, dropped included  |
| `xflow_receiver_bytes_total`                        | Counter | Payload bytes received per `listener`                |
| `xflow_receiver_read_errors_total`                  | Counter | Socket read failures per `listener`                  |
| `xflow_receiver_dropped_packets_total`              | Counter | Drops per `listener` and `reason` before decoding    |
| `xflow_receiver_queue_length`                       | Gauge   | Datagrams waiting between read loops and decoders    |
| `xflow_receiver_queue_capacity`                     | Gauge   | Bound of that queue                                  |
| `xflow_flows_total`                                 | Counter | Records decoded per `exporter` and `version`         |
| `xflow_decode_errors_total`                         | Counter | Rejections per `exporter`, `version` and `reason`    |
| `xflow_last_flow_timestamp_seconds`                 | Gauge   | Unix time of the exporter's last decoded datagram    |
| `xflow_templates`                                   | Gauge   | Unexpired templates per `exporter`, `odid`, `type`   |
| `xflow_sequence_missed_total`                       | Counter | Export packets lost per `exporter` and `odid`        |
| `xflow_sampling_rate`                               | Gauge   | Declared sampling rate, absent until one arrives     |
| `xflow_domains_refused_total`                       | Counter | Observation domains refused at the per-device budget |
| `xflow_aggregation_entries`                         | Gauge   | Entries held per `aggregation` table                 |
| `xflow_aggregation_evictions_total`                 | Counter | Idle entries evicted per `aggregation`               |
| `xflow_aggregation_overflow_records_total`          | Counter | Records folded into `other` by the entry bound       |
| `xflow_enrichment_lookups_total`                    | Counter | Records per `enricher` and `result`                  |
| `xflow_remote_write_sends_total`                    | Counter | Writes the remote endpoint accepted                  |
| `xflow_remote_write_failures_total`                 | Counter | Writes that failed                                   |
| `xflow_remote_write_samples_total`                  | Counter | Series shipped                                       |
| `xflow_remote_write_last_success_timestamp_seconds` | Gauge   | Unix time of the last accepted write                 |

### Reason values

`xflow_decode_errors_total` carries one of a closed set of reasons:

| Reason                    | Meaning                                          |
| :------------------------ | :----------------------------------------------- |
| `unsupported_version`     | A datagram no decoder claims                     |
| `malformed`               | A structure that does not fit its bytes          |
| `unsupported_aggregation` | A NetFlow v8 method outside the fourteen known   |
| `missing_template`        | A v9/IPFIX template that has not arrived yet     |
| `invalid_template`        | A template announcement the parser limits refuse |
| `reserved_set`            | A flowset in the reserved 2-255 range            |
| `domain_limit`            | An observation domain past the device's budget   |

`xflow_receiver_dropped_packets_total` carries one of two:

| Reason       | Meaning                                             |
| :----------- | :-------------------------------------------------- |
| `queue_full` | A burst the queue could not absorb                  |
| `truncated`  | A datagram larger than `--receiver.max-packet-size` |

**Freshness** — alert on `time() - xflow_last_flow_timestamp_seconds`: a silent device stops moving its timestamp while every counter freezes, and nothing else can tell that from a healthy quiet network.
