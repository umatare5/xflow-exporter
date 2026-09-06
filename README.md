<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./docs/assets/logo_dark.png" width="115px" />
    <source media="(prefers-color-scheme: light)" srcset="./docs/assets/logo.png" width="115px" />
    <img alt="xflow-exporter" src="./docs/assets/logo.png" width="115px" />
  </picture>

  <h1>xflow-exporter</h1>

  <p>A Prometheus Exporter for traffic flows: NetFlow, IPFIX and sFlow.</p>

  <p>
    <img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/umatare5/xflow-exporter?label=Latest%20version" />
    <a href="https://github.com/umatare5/xflow-exporter/actions/workflows/go-test-build.yml"><img alt="Test and Build" src="https://github.com/umatare5/xflow-exporter/actions/workflows/go-test-build.yml/badge.svg?branch=main" /></a>
    <a href="https://github.com/umatare5/xflow-exporter/actions/workflows/go-vulncheck.yml"><img alt="govulncheck" src="https://github.com/umatare5/xflow-exporter/actions/workflows/go-vulncheck.yml/badge.svg?branch=main" /></a><br>
    <img alt="Test Coverage" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/coverage.svg" />
    <a href="https://www.bestpractices.dev/projects/14363"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/14363/badge" /></a>
    <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" /></a>
  </p>

</div>

## Overview

This exporter receives flow records from on-premises devices and publishes Prometheus metrics.

- 🔬 **Auditable Sampling**: Counts scaled by the rate in force, which is published where declared
- 🏷️ **Enriched Labels**: Applications, ASNs, countries, threats and device names, from local files
- 📊 **Native Histograms**: Flow size and duration quantiles within five percent, Prometheus 3.8+
- 🧮 **In-Memory Aggregation**: Bounded-cardinality tables with Top-K and idle eviction

## Architecture

Devices push flow datagrams into the exporter, and Prometheus pulls aggregates out of it.

<picture>
  <img alt="Devices push flow datagrams into the exporter, and Prometheus pulls aggregates out of it" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/readme_architecture.png" width="705px">
</picture>

> [!NOTE]
> A scrape reads the in-memory tables and never waits on flow arrival. See [Push and Pull](docs/README.md#push-and-pull).

## Quick Start

### 1. Point your devices at the exporter

Configure each device to export flows to the exporter's IP on `4739/udp`, which is the default because that is the port IANA registers for IPFIX.

> [!TIP]
> **NetFlow v5, v8, v9 and sFlow reach that same port.** One listener takes every supported protocol, so a legacy exporter needs no port of its own. See [Version identification](docs/protocols.md#version-identification) for how a datagram is told apart.

### 2. Run the exporter with Docker

```bash
docker run -p 10053:10053 -p 4739:4739/udp ghcr.io/umatare5/xflow-exporter:latest
```

> [!TIP]
> If you prefer using binaries, download them from the [Release](https://github.com/umatare5/xflow-exporter/releases).
>
> **Supported Platform:** `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64` and `windows_amd64`

### 3. Scrape it

See [Prometheus Configuration](#prometheus-configuration) for the job and the alerting rules.

## Supported Protocols

NetFlow v5/v8/v9, IPFIX and sFlow v5, over plaintext UDP. See [Protocols](docs/protocols.md) for the wire formats and the devices each decoder was read against.

## Collectors

Each collector is off by default and enabled by its own `--collector.<name>` flag.

| Collector                   | Publishes                                                     |
| :-------------------------- | :------------------------------------------------------------ |
| `--collector.exporters`     | Per-device traffic by `exporter_address` and `version`        |
| `--collector.hosts`         | Traffic per source-destination address pair                   |
| `--collector.services`      | Traffic per address pair, protocol and port                   |
| `--collector.destinations`  | Traffic per destination address, protocol and port            |
| `--collector.tcp-flags`     | Traffic per TCP control-bit profile                           |
| `--collector.dscp`          | Traffic per DSCP class, from the TOS byte or the code point   |
| `--collector.asns`          | Traffic per AS pair, exported or from `--enrich.asn-database` |
| `--collector.applications`  | Traffic per application, exported or from `--enrich.services` |
| `--collector.countries`     | Traffic per country pair, needs `--enrich.country-database`   |
| `--collector.threats`       | Traffic per flagged address, needs `--enrich.threat-file`     |
| `--collector.distributions` | Flow size and duration native histograms                      |

> [!NOTE]
> `--enrich.*` sources fill what a device did not export, from local files. See [Enrichment](docs/enrichment.md).

## Flags

`xflow-exporter --help` prints every flag, and [`docs/help.md`](docs/help.md) carries the same list with notes.

- `--receiver.*`, `--parser.*` and `--aggregation.*` bound the receive path. See [Push and pull](docs/README.md#push-and-pull).
- `--enrich.*` names the local files that fill labels. See [Enrichment](docs/enrichment.md).
- `--remote-write.*` ships the registry to a Remote Write 2.0 endpoint. See [Remote write](docs/README.md#remote-write).
- `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD` fill the two auth flags.
- Either variable keeps the credential off the process table. See [Help](docs/help.md#notes).

## Endpoints

The exporter serves these endpoints:

- `/` — landing page, which confirms the exporter is up when reached at <http://localhost:10053/>
- `/metrics` — metrics endpoint, configurable via `--web.telemetry-path`
- `/healthz` — liveness probe, which returns a static 200 and deliberately ignores flow reception
- `/-/reload` — re-reads the enrichment sources on POST or PUT, needs `--web.enable-lifecycle`

See [Endpoints](docs/README.md#endpoints) for the method and status each one keeps, and [Reloading](docs/enrichment.md#reloading) for what a reload does.

## Metrics

Eleven collectors aggregate the flows, and the catalogues live in `docs/`:

| Page                                  | Covers                                                        |
| :------------------------------------ | :------------------------------------------------------------ |
| **[Collectors](docs/collectors.md)**  | The eleven collectors, their metrics and their labels         |
| **[Exporter health](docs/health.md)** | Reception, decoding, aggregation, enrichment and remote write |

The series a dashboard usually starts from:

| Collector       | Metric                          | Type      | Description            |
| :-------------- | :------------------------------ | :-------- | :--------------------- |
| `exporters`     | `xflow_exporter_bytes_total`    | Counter   | Traffic per device     |
| `hosts`         | `xflow_host_pair_bytes_total`   | Counter   | Top talkers            |
| `services`      | `xflow_service_bytes_total`     | Counter   | Top conversations      |
| `applications`  | `xflow_application_bytes_total` | Counter   | Traffic by application |
| `distributions` | `xflow_flow_bytes`              | Histogram | Flow size distribution |

> [!NOTE]
> See [`docs/README.md`](docs/README.md) for the absence, folding and sampling rules every collector shares.

> [!IMPORTANT]
> All collectors are **disabled by default** to bound cardinality, and `distributions` needs Prometheus v3.8+ with native histogram ingestion enabled in the scrape configuration. A minor release may rename or remove a series, change a default or drop a built-in application. Copying a new label back onto the old one with `metric_relabel_configs` keeps a rule written against the old name evaluating across the upgrade.

### Exporter Health Metrics

These series describe the exporter itself rather than the traffic it aggregates. They take no collector flag. [`docs/health.md`](docs/health.md) carries the whole set with its labels, its reason values and what to alert on.

| Metric                                 | Type    | Description                            |
| :------------------------------------- | :------ | :------------------------------------- |
| `xflow_flows_total`                    | Counter | Records decoded per device and version |
| `xflow_decode_errors_total`            | Counter | Rejections per device and reason       |
| `xflow_last_flow_timestamp_seconds`    | Gauge   | Unix time of the last decode           |
| `xflow_receiver_dropped_packets_total` | Counter | Pre-decode drops per listener          |
| `xflow_sampling_rate`                  | Gauge   | Declared rate per domain               |
| `xflow_aggregation_entries`            | Gauge   | Entries held per collector             |

> [!NOTE]
> Alert on freshness with `time() - xflow_last_flow_timestamp_seconds`, the only signal that separates a silent device from a quiet network.
>
> `--remote-write.url` adds four `xflow_remote_write_*` series, catalogued on the same page.

## Examples

### Command Lines

With no collector enabled the receiver counts every datagram and publishes no traffic series:

```bash
$ ./xflow-exporter --log.format text
time=2026-08-26T19:58:24.288+09:00 level=INFO msg="Starting xflow-exporter" version=0.1.0 listen_address=0.0.0.0 listen_port=10053 telemetry_path=/metrics
time=2026-08-26T19:58:24.291+09:00 level=INFO msg="Flow receiver listening" listener=:4739
time=2026-08-26T19:58:24.292+09:00 level=INFO msg="HTTP server listening" addr=0.0.0.0:10053
```

The three collectors a dashboard usually starts from:

```bash
./xflow-exporter --collector.exporters --collector.hosts --collector.services
```

For complete monitoring, see [`.air.toml`](https://github.com/umatare5/xflow-exporter/blob/main/.air.toml), which enables every collector.

### Prometheus Configuration

#### Job Configuration Example

Add the job from [`examples/prometheus.yml`](./examples/prometheus.yml) to your Prometheus configuration.

#### Recording Rules Configuration Example

Add the rules from [`examples/prometheus_record_rules.yml`](./examples/prometheus_record_rules.yml) to your Prometheus configuration.

#### Alerting Rules Configuration Example

Add the rules from [`examples/prometheus_alert_rules.yml`](./examples/prometheus_alert_rules.yml) to your Prometheus configuration.

### Grafana Dashboard

Import [`examples/grafana_xflow-exporter-dashboard.json`](./examples/grafana_xflow-exporter-dashboard.json). Data source and devices are variables.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard.png">
  <img alt="Grafana dashboard showing flow volume, composition and exporter health panels" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard.png">
</picture>

> [!TIP]
> See [`docs/assets/xflow-exporter-dashboard_full.png`](https://github.com/umatare5/xflow-exporter/blob/main/docs/assets/xflow-exporter-dashboard_full.png) for the full capture image of the example.

> [!NOTE]
> Panels rank by packets rather than bytes, and the composition panels rank rather than total. See [Dashboards](docs/README.md#dashboards) for what each panel covers and why.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the `make` targets, the Docker build and the release process.

## License

MIT. The binary statically links Apache-2.0, MIT, ISC and BSD 3-Clause dependencies, whose notices are reproduced in [`NOTICE`](NOTICE) and shipped alongside [`LICENSE`](LICENSE) in every release archive and container image.
