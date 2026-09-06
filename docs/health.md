# Exporter Health

This is the whole set of `xflow_` series the exporter publishes about itself. None takes a collector flag. The aggregation series appear while any collector is enabled, the enrichment series while their `--enrich.*` source is set, and the remote-write series while `--remote-write.url` is set.

`--collector.internal.go-runtime` and `--collector.internal.process` add client_golang's `go_*` and `process_*` families to the same registry, which carry no `xflow_` prefix and are not catalogued here.

## Metrics

| Subsystem      | Metric                                              | Type    | Description               |
| :------------- | :-------------------------------------------------- | :------ | :------------------------ |
| `build`        | `xflow_build_info`                                  | Gauge   | Version, always 1         |
| `receiver`     | `xflow_receiver_packets_total`                      | Counter | Datagrams per `listener`  |
| `receiver`     | `xflow_receiver_bytes_total`                        | Counter | Bytes per `listener`      |
| `receiver`     | `xflow_receiver_read_errors_total`                  | Counter | Errors per `listener`     |
| `receiver`     | `xflow_receiver_dropped_packets_total`              | Counter | Drops per `listener`      |
| `receiver`     | `xflow_receiver_queue_length`                       | Gauge   | Datagrams queued          |
| `receiver`     | `xflow_receiver_queue_capacity`                     | Gauge   | Bound of that queue       |
| `decoder`      | `xflow_flows_total`                                 | Counter | Records per `version`     |
| `decoder`      | `xflow_decode_errors_total`                         | Counter | Rejections per `reason`   |
| `decoder`      | `xflow_last_flow_timestamp_seconds`                 | Gauge   | Unix time, last decode    |
| `decoder`      | `xflow_templates`                                   | Gauge   | Templates per `type`      |
| `decoder`      | `xflow_sequence_missed_total`                       | Counter | Packets or records lost   |
| `decoder`      | `xflow_sampling_rate`                               | Gauge   | Declared sampling rate    |
| `decoder`      | `xflow_domains_refused_total`                       | Counter | Past the domain budget    |
| `decoder`      | `xflow_vendor_strings_refused_total`                | Counter | Unrepresentable strings   |
| `decoder`      | `xflow_applications_refused_total`                  | Counter | Past the app budget       |
| `decoder`      | `xflow_exporters_refused_total`                     | Counter | Past the device budget    |
| `aggregation`  | `xflow_aggregation_entries`                         | Gauge   | Entries per `aggregation` |
| `aggregation`  | `xflow_aggregation_evictions_total`                 | Counter | Idle entries evicted      |
| `aggregation`  | `xflow_aggregation_overflow_records_total`          | Counter | Folded into `other`       |
| `enrichment`   | `xflow_enrichment_lookups_total`                    | Counter | Records per `enricher`    |
| `enrichment`   | `xflow_threat_entries`                              | Gauge   | Flagged addresses held    |
| `enrichment`   | `xflow_threat_skipped_lines`                        | Gauge   | Lines naming no address   |
| `enrichment`   | `xflow_threat_reloads_total`                        | Counter | List loads that succeeded |
| `enrichment`   | `xflow_threat_reload_failures_total`                | Counter | List loads that failed    |
| `remote_write` | `xflow_remote_write_sends_total`                    | Counter | Writes accepted           |
| `remote_write` | `xflow_remote_write_failures_total`                 | Counter | Writes that failed        |
| `remote_write` | `xflow_remote_write_samples_total`                  | Counter | One sample per series     |
| `remote_write` | `xflow_remote_write_last_success_timestamp_seconds` | Gauge   | Unix time, last accepted  |

## Labels

`exporter_address` and `version` carry what [Collectors](collectors.md#labels) says. The `remote_write` series carry none.

**`version`** on `xflow_build_info`

the exporter's release rather than a flow protocol, sharing no series with the other meaning.

**`listener`**

the receive address a datagram arrived on, spelled as `--receiver.address` configured it.

**`odid`**

the observation domain inside one exporter and protocol.

- NetFlow v9 says Source ID, IPFIX says Observation Domain ID and sFlow says sub-agent id, so spelling out any one of them would put that protocol's word on a series whose `version` names another.

**`type`**

which kind of template a count covers, `template` or `options_template`.

**`reason`**

what a refusal was, from the closed set the carrying series tabulates under Specifications.

**`aggregation`**

the table a size or an eviction count belongs to, named as its collector is: `exporters`, `hosts`, `services`, `destinations`, `tcp_flags`, `dscp`, `asns`, `applications`, `countries` or `threats`.

**`enricher`/`result`**

which source a lookup went through — `asn`, `country`, `mapping`, `services` or `threat`. `result` says what that source made of the record. `filled` supplied a dimension, `unknown` says the source knew nothing, and `skipped` says the device or an earlier source in the chain had carried it already.

- `mapping` runs ahead of `services`, so a port both name is filled by `mapping` and leaves `services` `skipped` — [Service names](enrichment.md#service-names) carries the precedence.
- A port only `services` names was already counted `unknown` by the earlier `mapping` lookup, which cannot know that a later source will name the same port.
- A mapping file carrying `devices:` alone names no port, so `mapping` reads `unknown` on every record whose service the device did not itself supply. The file's device and interface names ride the naming series rather than a lookup.

## Specifications

Each entry carries what the HELP text and the shared [Absence](README.md#absence) rules do not.

**`xflow_build_info`**

it is registered before any collector, and the receiver and decoder series beside it whatever the collector flags say, so a scrape on an exporter with nothing enabled still carries all three.

**`xflow_receiver_packets_total`**

it counts what a read loop took off the socket, dropped datagrams included, so the drop share is `xflow_receiver_dropped_packets_total` over it rather than a difference against the decoded count.

- A datagram the kernel discarded before that read reaches neither series, so a receive-buffer overflow shows only in the socket's own statistics.

**`xflow_receiver_dropped_packets_total`**

its `reason` names one of two, both counted before any decoder reads the datagram.

| Reason       | Meaning                                      |
| :----------- | :------------------------------------------- |
| `queue_full` | A burst the queue could not absorb           |
| `truncated`  | A datagram past `--receiver.max-packet-size` |

**`xflow_receiver_queue_length` and `xflow_receiver_queue_capacity`**

neither carries a `listener`, the queue being one for every read loop, so the ratio between them is what says whether the decoders are keeping up with the receive path.

**`xflow_flows_total`, `xflow_decode_errors_total` and `xflow_last_flow_timestamp_seconds`**

all three are keyed by the device, so a device refused at the exporter budget reaches none of them while its datagrams still decode and still feed every aggregation table.

- Alert per device on `time() - xflow_last_flow_timestamp_seconds`: a device that stopped exporting freezes its instant along with every counter it feeds, and no other series separates that from a quiet link.

**`xflow_decode_errors_total`**

its `reason` names what the decoder refused rather than where it stopped.

| Reason                    | Meaning                                      |
| :------------------------ | :------------------------------------------- |
| `unsupported_version`     | A datagram no decoder claims                 |
| `malformed`               | A structure that does not fit its bytes      |
| `unsupported_aggregation` | A NetFlow v8 method not among the fourteen   |
| `missing_template`        | A v9/IPFIX template that has not arrived yet |
| `invalid_template`        | A template announcement the parser refuses   |
| `reserved_set`            | A set id its protocol leaves unassigned      |
| `domain_limit`            | An observation domain past the device budget |

**`xflow_templates`, `xflow_sequence_missed_total` and `xflow_sampling_rate`**

all three carry `exporter_address`, `version` and `odid` together. A domain is that triple rather than the identifier alone. The three protocols number their domains independently, so one number from one device names as many domains as that device speaks protocols.

- Dropping `version` from the triple would hand two domains one label set, and a registry refuses to gather a duplicate, so the whole scrape would fail rather than one domain's series.
- `xflow_sampling_rate` reads a v9 or IPFIX options declaration alone, so a v5 or sFlow device corrects its counts with no rate series to audit them by — [Sampling correction](README.md#sampling-correction) carries the precedence.
- `xflow_sequence_missed_total` counts what each sequence number counts, packets on v9 and sFlow and data records on IPFIX, so one lost IPFIX message adds every record it carried.
- A rise here is loss or reordering on the wire rather than a race between the decoders — [Push and pull](README.md#push-and-pull) carries why one worker holds each device.

**the four `_refused_total` counters**

three of them name a budget the wire cannot raise and count attempts rather than the entities refused — [Bounded state](README.md#bounded-state) carries the budgets and what a refusal costs the records behind it. `xflow_vendor_strings_refused_total` counts a string the exporter cannot publish instead, longer than 255 bytes or not valid UTF-8, once per field rather than once per string.

**`xflow_enrichment_lookups_total`**

it counts the records each source saw rather than the lookups it made, so `skipped` rises on a record the device or an earlier source had already filled, with no lookup performed. `unknown` is the ordinary reading for a source that covers only part of the traffic, so the split reads as coverage rather than as failure.

**`xflow_threat_entries`, `xflow_threat_skipped_lines` and the two reload counters**

a failed load keeps the previous set on purpose, so a rise in `xflow_threat_reload_failures_total` says the set in force is older than the file on disk — [Reloading](enrichment.md#reloading) carries why.

- `xflow_threat_skipped_lines` counts what the load in force passed over, a list published in CIDR notation being the usual cause, so it reads as the gap between the file and the set rather than as an error.

**the four `xflow_remote_write_*` series**

they cover the shipping path, which runs on `--remote-write.interval` rather than on a scrape. A rejected write leaves `/metrics` and `up` untouched, so only the failure counter records it.

- The failure counter is what an alert reads, not the timestamp. `xflow_remote_write_last_success_timestamp_seconds` is absent until the first accepted write, so a client that has never reached its endpoint publishes no instant to go stale.
- A registry gather that fails counts on the same failure counter, nothing having been sent.
- `xflow_remote_write_samples_total` rises by one per series per write, so its increase over the sends counter is the series count each write carried — [Remote write](README.md#remote-write) carries what a store accumulates.
