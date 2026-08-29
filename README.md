<div align="center">

  <h1>xflow-exporter</h1>

  <p>A Prometheus Exporter for traffic flows: NetFlow, IPFIX and sFlow.</p>

</div>

## Overview

This exporter receives traffic flow records from on-premises network devices — Cisco Catalyst and Nexus, Juniper SRX and MX, Arista, Palo Alto Networks — and serves Prometheus metrics aggregated from them.

- 📥 **Push-to-Pull Bridge**: Receives UDP flow exports and serves them to Prometheus scrapes
- 🧮 **In-Memory Aggregation**: Bounded-cardinality tables with Top-K and idle eviction
- 🧭 **Router-Scoped Parsing**: Template caches keyed by exporter address and Observation Domain ID
- 📊 **Native Histograms**: Flow size and duration distributions in single series

> [!IMPORTANT]
> This project is pre-1.0: a minor release may rename or remove a metric. Read the [CHANGELOG](CHANGELOG.md) before upgrading.

## Quick Start

### 1. Point your devices at the exporter

Configure each device to export flows to the exporter's address, UDP port 2055 by default. Every listener accepts every supported protocol, identified per datagram.

### 2. Run the exporter with Docker

```bash
docker run -p 10040:10040 -p 2055:2055/udp   ghcr.io/umatare5/xflow-exporter:latest   --collector.exporters --collector.hosts
```

> [!Tip]
> If you prefer using binaries, download them from the [release page](https://github.com/umatare5/xflow-exporter/releases).
>
> Supported Platforms are: `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64` and `windows_amd64`

### 3. Scrape it

Add a job for `localhost:10040` using [examples/prometheus.yml](examples/prometheus.yml) as a reference, and the alerting rules from [examples/prometheus_alert_rules.yml](examples/prometheus_alert_rules.yml).

## Protocol Support

| Protocol                        | Status    |
| :------------------------------ | :-------- |
| NetFlow v5 (incl. J-Flow v5)    | Supported |
| NetFlow v8 (incl. J-Flow v8)    | Supported |
| NetFlow v9 (incl. FNF, J-Flow)  | Supported |
| NetFlow-Lite (packet sections)  | Supported |
| IPFIX / NetFlow v10             | Supported |
| sFlow v5                        | Supported |

NetFlow v8 covers all fourteen aggregation methods of aggregation export version 2. A v8 record is pre-aggregated on the router, so it carries only its method's dimensions and the rest stay absent.

NetFlow v9 and IPFIX templates are cached per exporter address and Observation Domain ID together, as RFC 7011 requires, so two domains reusing one template ID never corrupt each other. A template is refused when it declares a zero-width fixed field or more than `--parser.max-fields-per-template` fields, and expires after `--parser.template-ttl` without a re-announcement. IPFIX adds enterprise information elements, variable-length fields with strict bounds checking, and template withdrawals.

NetFlow-Lite (Catalyst 2960-X/XR, 2960-CX, 3560-CX, 4948E) ships sampled packet sections inside v9 or IPFIX records: the deprecated v9 field 104 as measured on the devices, and the IANA elements 315/313/312 in IPFIX mode. Sections decode through the same header walk the sFlow decoder uses, fields the device parsed itself win over the section, and the 309/310 random-sampler options pair feeds the sampling correction.

sFlow v5 decodes flow samples, compact and expanded, from the raw Ethernet header — through stacked VLAN tags to IPv4/IPv6 and the TCP/UDP ports — and from the pre-parsed sampled IPv4/IPv6 records. Counter samples are out of scope: they carry interface statistics, not traffic. A sampled header cut short keeps the layers that decoded and leaves the rest absent.

Options templates feed the packet sampling rate — the PSAMP interval/space pair, the random-sampler interval, or the legacy interval, in that order — which is stamped onto decoded records and published as `xflow_sampling_rate`. Cisco AVC application tables announced through options resolve the `applicationId` (IE 95) of each record into the name and category the device itself declared, and PAN-OS App-ID and User-ID strings are carried through a string interner so one name allocates once rather than per flow.

Transport is plaintext UDP. DTLS is not supported: no shipping network OS exports flows over DTLS, and Go has no production DTLS 1.3 implementation yet.

## Syntax

`xflow-exporter --help` prints every flag, and [docs/configuration.md](docs/configuration.md) carries the same list.

Each data collector is enabled per module, all off by default:

| Module                      | Publishes                                        |
| :-------------------------- | :----------------------------------------------- |
| `--collector.exporters`     | Per-device traffic by `exporter` and `version`   |
| `--collector.hosts`         | Traffic per source-destination address pair      |
| `--collector.services`      | Traffic per address pair, protocol and port      |
| `--collector.asns`          | Traffic per AS pair from device-exported numbers |
| `--collector.applications`  | Traffic per AVC / App-ID / applicationId name    |
| `--collector.distributions` | Flow size and duration native histograms         |

The operational knobs live under `--receiver.*` (listeners, batching, queue), `--parser.*` (template limits) and `--aggregation.*` (entry TTL, bounds, Top-K, byte threshold).

On Linux the read loops use `recvmmsg` batching; other platforms read one datagram per call, so performance figures are Linux figures. Transport is plaintext UDP — no shipping network OS exports flows over DTLS, and Go has no production DTLS 1.3 implementation yet.

## Endpoints

The exporter serves three endpoints:

- `/` — landing page, which confirms the exporter is running when reached at <http://localhost:10040/>
- `/metrics` — metrics endpoint, configurable via `--web.telemetry-path`
- `/healthz` — liveness probe, which returns a static 200 and deliberately ignores flow reception

## Metrics

### Traffic Metrics

Every module is **disabled by default** and enabled per `--collector.*` flag. Each table family carries `_bytes_total`, `_packets_total` and `_flows_total`; bytes and packets are sampling-corrected, flow counts stay as exported.

| Module          | Metric family (representative)   | Labels                            |
| :-------------- | :------------------------------- | :-------------------------------- |
| `exporters`     | `xflow_exporter_bytes_total`     | `exporter,version`                |
| `hosts`         | `xflow_host_pair_bytes_total`    | `exporter,src,dst`                |
| `services`      | `xflow_service_bytes_total`      | `exporter,src,dst,proto,port`     |
| `asns`          | `xflow_asn_pair_bytes_total`     | `exporter,src_asn,dst_asn`        |
| `applications`  | `xflow_application_bytes_total`  | `exporter,application`            |
| `distributions` | `xflow_flow_bytes`               | `exporter` — native histogram     |

Cardinality is bounded three ways, and everything folded lands in a single series whose labels read `other`: the entry bound (`--aggregation.max-entries`) folds new keys at ingest, the Top-K bound (`--aggregation.top-k`) and the byte threshold (`--aggregation.min-bytes`) fold the tail at scrape time. An entry idle past `--aggregation.entry-ttl` is evicted and its series disappears — a flow nobody has seen is gone, not zero. A record lacking an aggregation's dimensions feeds no series there.

`distributions` publishes `xflow_flow_bytes` and `xflow_flow_duration_seconds` as **native histograms**: scraping them needs Prometheus v3.8+ with native histogram ingestion enabled in the scrape configuration.

### Exporter Health Metrics

These series describe the exporter itself. They have no module and no collector flag.

| Metric                                     | Type    | Description                                          |
| :----------------------------------------- | :------ | :--------------------------------------------------- |
| `xflow_build_info`                         | Gauge   | Exporter version in the `version` label, always 1    |
| `xflow_receiver_packets_total`             | Counter | Datagrams received per `listener`, dropped included  |
| `xflow_receiver_bytes_total`               | Counter | Payload bytes received per `listener`                |
| `xflow_receiver_read_errors_total`         | Counter | Socket read failures per `listener`                  |
| `xflow_receiver_dropped_packets_total`     | Counter | Drops per `listener` and `reason` before decoding    |
| `xflow_receiver_queue_length`              | Gauge   | Datagrams waiting between read loops and decoders    |
| `xflow_receiver_queue_capacity`            | Gauge   | Bound of that queue                                  |
| `xflow_flows_total`                        | Counter | Records decoded per `exporter` and `version`         |
| `xflow_decode_errors_total`                | Counter | Rejections per `exporter`, `version` and `reason`    |
| `xflow_last_flow_timestamp_seconds`        | Gauge   | Unix time of the exporter's last decoded datagram    |
| `xflow_templates`                          | Gauge   | Unexpired templates per `exporter`, `odid`, `type`   |
| `xflow_sequence_missed_total`              | Counter | Export packets lost per `exporter` and `odid`        |
| `xflow_sampling_rate`                      | Gauge   | Declared sampling rate, absent until one arrives     |
| `xflow_aggregation_entries`                | Gauge   | Entries held per `aggregation` table                 |
| `xflow_aggregation_evictions_total`        | Counter | Idle entries evicted per `aggregation`               |
| `xflow_aggregation_overflow_records_total` | Counter | Records folded into `other` by the entry bound       |

On `xflow_receiver_dropped_packets_total`, `reason` is `queue_full` for a burst the queue could not absorb and `truncated` for a datagram larger than `--receiver.max-packet-size`. Both series are seeded at 0, so a first drop is a rise on a series that was already there.

On `xflow_decode_errors_total`, `reason` is `unsupported_version` for a datagram no decoder claims, `malformed` for one whose claimed structure does not fit its bytes, and `unsupported_aggregation` for a NetFlow v8 aggregation method outside the fourteen this exporter knows. The template protocols add `missing_template`, expected after a restart until each device re-announces; `invalid_template` for an announcement the limits refuse; and `reserved_set` for a flowset in the reserved 2-255 range. Exporter-labeled series appear on a device's first datagram: a push protocol cannot know its senders in advance.

Alert on freshness with `time() - xflow_last_flow_timestamp_seconds`: a device that goes silent stops moving its timestamp while every counter freezes, and nothing else can tell that from a healthy quiet network.

With no `--collector.*` module enabled, decoded records are counted by the health series and discarded.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the `make` targets, the Docker build, the release process and how to open a pull request.

## Licence

[MIT](LICENSE). The binary statically links Apache-2.0, MIT and BSD 3-Clause dependencies, whose notices are reproduced in [NOTICE](NOTICE) and shipped alongside `LICENSE` in every release archive and container image.
