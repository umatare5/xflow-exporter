# Exporter Health

This documentation provides an overview of the health metrics exposed by the xflow-exporter.

## Metrics

The following table lists the metrics exposed by each subsystem.

- Only the `build`, `receiver` and `decoder` subsystems are registered inherently.
- Other subsystems are initialized conditionally based on collector and configuration flags.

| Subsystem      | Metric                                              | Type    | Description                    |
| :------------- | :-------------------------------------------------- | :------ | :----------------------------- |
| `build`        | `xflow_build_info`                                  | Gauge   | The release, always 1          |
| `receiver`     | `xflow_receiver_packets_total`                      | Counter | Datagrams read, drops included |
| `receiver`     | `xflow_receiver_bytes_total`                        | Counter | Payload bytes read             |
| `receiver`     | `xflow_receiver_read_errors_total`                  | Counter | Socket read failures           |
| `receiver`     | `xflow_receiver_dropped_packets_total`              | Counter | Drops before decoding          |
| `receiver`     | `xflow_receiver_queue_length`                       | Gauge   | Datagrams waiting to decode    |
| `receiver`     | `xflow_receiver_queue_capacity`                     | Gauge   | Bound of that queue            |
| `decoder`      | `xflow_flows_total`                                 | Counter | Records decoded                |
| `decoder`      | `xflow_decode_errors_total`                         | Counter | Rejections per `reason`        |
| `decoder`      | `xflow_last_flow_timestamp_seconds`                 | Gauge   | Unix time, last record         |
| `decoder`      | `xflow_last_datagram_timestamp_seconds`             | Gauge   | Unix time, last datagram       |
| `decoder`      | `xflow_templates`                                   | Gauge   | Unexpired templates per `type` |
| `decoder`      | `xflow_sequence_missed_total`                       | Counter | Packets or records lost        |
| `decoder`      | `xflow_flow_clock_inversions_total`                 | Counter | Flows ending before they began |
| `decoder`      | `xflow_sampling_rate`                               | Gauge   | Rate in force per domain       |
| `decoder`      | `xflow_sampler_rate`                                | Gauge   | Rate per declared sampler      |
| `decoder`      | `xflow_sampling_unresolved_flows_total`             | Counter | Records taken uncorrected      |
| `decoder`      | `xflow_sample_pool_packets_total`                   | Counter | Packets the samplers saw       |
| `decoder`      | `xflow_samples_dropped_total`                       | Counter | Samples the agent lost         |
| `decoder`      | `xflow_samplers_refused_total`                      | Counter | Samples left untracked         |
| `decoder`      | `xflow_sampling_declarations_refused_total`         | Counter | Declarations discarded         |
| `decoder`      | `xflow_domains_refused_total`                       | Counter | Datagrams refused a domain     |
| `decoder`      | `xflow_vendor_strings_refused_total`                | Counter | Unpublishable string fields    |
| `decoder`      | `xflow_applications_refused_total`                  | Counter | Announcements refused          |
| `decoder`      | `xflow_exporters_refused_total`                     | Counter | Datagrams left unattributed    |
| `aggregation`  | `xflow_aggregation_entries`                         | Gauge   | Entries per `aggregation`      |
| `aggregation`  | `xflow_aggregation_evictions_total`                 | Counter | Idle entries evicted           |
| `aggregation`  | `xflow_aggregation_overflow_records_total`          | Counter | Records folded into `other`    |
| `enrichment`   | `xflow_enrichment_lookups_total`                    | Counter | Records per `enricher`         |
| `enrichment`   | `xflow_threat_entries`                              | Gauge   | Flagged addresses in force     |
| `enrichment`   | `xflow_threat_skipped_lines`                        | Gauge   | List lines naming no address   |
| `enrichment`   | `xflow_threat_reloads_total`                        | Counter | List loads that succeeded      |
| `enrichment`   | `xflow_threat_reload_failures_total`                | Counter | List loads that failed         |
| `remote_write` | `xflow_remote_write_sends_total`                    | Counter | Writes the endpoint accepted   |
| `remote_write` | `xflow_remote_write_failures_total`                 | Counter | Writes that failed             |
| `remote_write` | `xflow_remote_write_samples_total`                  | Counter | Samples sent, one per series   |
| `remote_write` | `xflow_remote_write_last_success_timestamp_seconds` | Gauge   | Unix time, last accepted       |

## Labels

Refer to the [Collectors](collectors.md#labels) for standard label definitions.

## Annotations

**`xflow_receiver_dropped_packets_total`**

Counts drops at queue handoff (`queue_full`) or size check (`truncated`). Socket buffer overflows are OS-level metrics and not exposed here.

**`xflow_receiver_queue_*`**

The ratio between `xflow_receiver_queue_length` and `xflow_receiver_queue_capacity` indicates decode processing latency.

**`xflow_decode_errors_total`**

Accounts for rejections based on version compatibility, aggregation methods, template validation, domain limits, and link layers the decoder does not walk.

**`xflow_last_*_timestamp_seconds`**

Updates on record decodes (`flow`) or any datagram arrival (`datagram`).

**`xflow_sequence_missed_total`**

Captures loss or reordering based on protocol sequence numbering.

**`xflow_flow_clock_inversions_total`**

Counts the records whose flow ended before it began, both instants withheld rather than published. A domain whose records carry no flow clock never reaches the check, so it publishes no series.

**`xflow_sampling_rate`**

Reflects the rate in force for a domain, declared by its own options or inherited from the device.

**`xflow_sampler_rate`**

Tracks each sampler a device declared, keyed per device and protocol rather than per domain.

**`xflow_sampling_unresolved_flows_total`**

Counts the v9 and IPFIX records that reached the end of the correction precedence with nothing to apply. Published only for a device that has declared a rate, because an uncorrected record and one corrected at 1:1 carry identical counts.

**`xflow_*_refused_total`**

Bounds state objects such as domains, applications, and exporters according to hard limits.

**`xflow_enrichment_lookups_total`**

Tracks what `asn`, `country`, `mapping`, `services`, `threat` and `vlan` made of the records they saw. `filled` resolved a dimension, `unknown` found no answer, and `skipped` needed none. Only `asn`, `mapping` and `services` ever skip, so the other three hold `skipped` at zero.

**`xflow_remote_write_*`**

Records endpoint write performance and limits observation exclusively to HTTP responses.

## Technical Notes

This section covers technical considerations and best practices for development, configuration, and operation.

**Domain Identification**: A domain is strictly defined by the triple `exporter_address`, `version`, and `odid`. Removing `version` could merge unrelated protocols on the same device. `odid` represents Source ID on v9, Observation Domain ID on IPFIX, and sub-agent ID on sFlow.

**Sampling Declarations**: `xflow_sampling_rate` tracks singular v9/IPFIX Options Templates, while `xflow_sampler_rate` resolves mappings for devices declaring multiple samplers, keyed per device and protocol. Auditing devices with multiple rates can be achieved via: `count by (exporter_address, version) (count_values by (exporter_address, version) ("rate", (xflow_sampling_rate or xflow_sampler_rate))) > 1`.

**Correction Precedence**: A record takes the rate of the sampler it names, failing that its own domain's declaration, and failing that the one rate every declaration on the device agrees on. Where none answers, the counts are corrected by one and no `xflow_sampling_rate` series exists, as on a device whose declarations disagree while its records name the samplers correcting them. `xflow_sampling_unresolved_flows_total` separates the two, appearing once the device has declared, so a restart leaves it absent until the device re-announces.

**Series Presence**: A series keyed by wire data appears on its first event, so `xflow_decode_errors_total`, `xflow_last_flow_timestamp_seconds` and `xflow_sampling_rate` read as absent rather than zero beforehand. The `_refused_total` counters are seeded at zero instead, a first refusal reading as a rise. `xflow_flow_clock_inversions_total` seeds at zero once a domain has anchored a flow clock.

**Sequence Tracking**: Protocol numbering schemes vary: `xflow_sequence_missed_total` counts packets for v9 and sFlow, but records for v5, v8, and IPFIX. Sequence loss tracking requires strict per-worker ordering, avoiding false positives across concurrent decoders.

**sFlow Pool Audits**: `xflow_sample_pool_packets_total` and `xflow_samples_dropped_total` track the sFlow agent's own counters. The actual delivered share can be audited via: `rate(xflow_flows_total{version="sflow_v5"}[5m]) / (rate(xflow_flows_total{version="sflow_v5"}[5m]) + sum without (odid) (rate(xflow_samples_dropped_total[5m])))`.

**State Boundaries**: Refusal bounds (`_refused_total`) are rigidly defined per device: Observation domains, Devices with decode stats, Announced applications, Sampler declarations, and Samplers per domain. `xflow_vendor_strings_refused_total` bounds strictly on length (>255 bytes) or UTF-8 invalidity.
