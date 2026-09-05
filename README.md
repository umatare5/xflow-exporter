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

This exporter receives flow records from on-premises devices and serves them as Prometheus metrics.

- 🔬 **Auditable Sampling**: Counts scaled by the rate in force, and that rate published where declared
- 🏷️ **Enriched Labels**: Applications, ASNs, countries, threats and device names, from local files
- 📊 **Native Histograms**: Flow size and duration quantiles within five percent, Prometheus 3.8+
- 🧮 **In-Memory Aggregation**: Bounded-cardinality tables with Top-K and idle eviction

## Architecture

Devices push flow datagrams into the exporter, and Prometheus pulls aggregates out of it.

<picture>
  <img alt="Devices push flow datagrams into the exporter, and Prometheus pulls aggregates out of it" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/readme_architecture.png" width="705px">
</picture>

A scrape reads the in-memory aggregation tables and never waits on flow arrival — see [`docs/README.md`](docs/README.md).

## Quick Start

### 1. Point your devices at the exporter

Configure each device to export flows to the exporter's IP, `4739/udp` by default — the port IANA registers for IPFIX.

> [!TIP]
> **NetFlow v5, v8, v9 and sFlow reach that same port.** Every datagram carries its own version, so one listener takes every supported protocol and a legacy exporter needs no port of its own.

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

## Protocol Support

NetFlow v5/v8/v9, IPFIX and sFlow v5, over plaintext UDP — see [Protocols](docs/protocols.md).

## Syntax

`xflow-exporter --help` prints every flag, and [`docs/help.md`](docs/help.md) carries the same list.

Each data collector is enabled per module:

| Module                      | Publishes                                              |
| :-------------------------- | :----------------------------------------------------- |
| `--collector.exporters`     | Per-device traffic by `exporter_address` and `version` |
| `--collector.hosts`         | Traffic per source-destination address pair            |
| `--collector.services`      | Traffic per address pair, protocol and port            |
| `--collector.destinations`  | Traffic per destination address, protocol and port     |
| `--collector.tcp-flags`     | Traffic per TCP control-bit profile                    |
| `--collector.dscp`          | Traffic per DSCP class from the exported TOS byte      |
| `--collector.asns`          | Traffic per AS pair from device-exported numbers       |
| `--collector.applications`  | Traffic per AVC / App-ID / applicationId name          |
| `--collector.countries`     | Traffic per country pair from a country database       |
| `--collector.threats`       | Traffic per flagged address, needs a list file         |
| `--collector.distributions` | Flow size and duration native histograms               |

`--receiver.*`, `--parser.*` and `--aggregation.*` tune the receive path — see [Push and pull](docs/README.md#push-and-pull).

## Endpoints

The exporter serves four endpoints:

- `/` — landing page, which confirms the exporter is running when reached at <http://localhost:10053/>
- `/metrics` — metrics endpoint, configurable via `--web.telemetry-path`
- `/healthz` — liveness probe, which returns a static 200 and deliberately ignores flow reception
- `/-/reload` — [re-reads the enrichment sources](docs/README.md#reloading) on POST or PUT, needs `--web.enable-lifecycle`

## Metrics

Eleven modules aggregate the flows, and the catalogues live in `docs/`:

| Page                                  | Covers                                                 |
| :------------------------------------ | :----------------------------------------------------- |
| **[Collectors](docs/collectors.md)**  | The ten table families, their metrics and their labels |
| **[Exporter health](docs/health.md)** | Reception, decoding, aggregation and enrichment        |

The series a dashboard usually starts from:

| Module          | Metric                          | Type             | Description            |
| :-------------- | :------------------------------ | :--------------- | :--------------------- |
| `exporters`     | `xflow_exporter_bytes_total`    | Counter          | Throughput per device  |
| `hosts`         | `xflow_host_pair_bytes_total`   | Counter          | Top talkers            |
| `services`      | `xflow_service_bytes_total`     | Counter          | Top conversations      |
| `applications`  | `xflow_application_bytes_total` | Counter          | Traffic by application |
| `distributions` | `xflow_flow_bytes`              | Native histogram | Flow size distribution |

See [`docs/README.md`](docs/README.md) for the absence, folding and sampling rules every module shares.

> [!IMPORTANT]
>
> All collector modules are **disabled by default** to bound cardinality, and `distributions` needs Prometheus v3.8+ with native histogram ingestion enabled in the scrape configuration.

### Exporter Health Metrics

These series describe the exporter itself rather than the traffic it aggregates. They have no module and no collector flag, and [`docs/health.md`](docs/health.md) carries the whole set with its labels and reason values.

| Metric                                 | Type    | Description                      |
| :------------------------------------- | :------ | :------------------------------- |
| `xflow_flows_total`                    | Counter | Records decoded per device       |
| `xflow_decode_errors_total`            | Counter | Rejections per device and reason |
| `xflow_last_flow_timestamp_seconds`    | Gauge   | Unix time of the last decode     |
| `xflow_receiver_dropped_packets_total` | Counter | Pre-decode drops per listener    |
| `xflow_sampling_rate`                  | Gauge   | Declared rate per domain         |
| `xflow_aggregation_entries`            | Gauge   | Entries held per table           |

> [!IMPORTANT]
>
> Alert on freshness with `time() - xflow_last_flow_timestamp_seconds`. A silent device stops moving its timestamp while every counter freezes, and nothing else can tell that from a healthy quiet network.

### Remote Write Metrics

These series describe the shipping path rather than the exporter, and appear only while `--remote-write.url` is set. See [Remote write](docs/README.md#remote-write) for what a long-term store accumulates and how to bound it.

| Metric                                              | Type    | Description                     |
| :-------------------------------------------------- | :------ | :------------------------------ |
| `xflow_remote_write_sends_total`                    | Counter | Writes the endpoint accepted    |
| `xflow_remote_write_failures_total`                 | Counter | Writes that failed              |
| `xflow_remote_write_samples_total`                  | Counter | One sample per series per write |
| `xflow_remote_write_last_success_timestamp_seconds` | Gauge   | Unix time of the last success   |

> [!IMPORTANT]
>
> Alert on `xflow_remote_write_failures_total` rather than on the timestamp. Shipping runs on its own interval, so a rejected write leaves `/metrics` and `up` untouched, and the timestamp is absent until the first write succeeds — a client that has never reached its endpoint publishes no instant to go stale. A registry gather that fails counts on that same counter.

## Use Cases

### Basic Usage - No Collectors

```bash
$ ./xflow-exporter --log.format text
time=2026-08-26T19:58:24.288+09:00 level=INFO msg="Starting xflow-exporter" version=0.1.0 listen_address=0.0.0.0 listen_port=10053 telemetry_path=/metrics
time=2026-08-26T19:58:24.291+09:00 level=INFO msg="Flow receiver listening" listener=:4739
time=2026-08-26T19:58:24.292+09:00 level=INFO msg="HTTP server listening" addr=0.0.0.0:10053
```

The receiver listens and the health series count every datagram, but no traffic series is published.

### Essential Usage

```bash
./xflow-exporter --collector.exporters --collector.hosts --collector.services
```

### Complete Usage

For complete monitoring, see [`.air.toml`](https://github.com/umatare5/xflow-exporter/blob/main/.air.toml) which enables every collector module.

### Prometheus Configuration

#### Job Configuration Example

Add the job from [`examples/prometheus.yml`](./examples/prometheus.yml) to your Prometheus configuration.

#### Recording Rules Configuration Example

Add the rules from [`examples/prometheus_record_rules.yml`](./examples/prometheus_record_rules.yml) to your configuration.

> [!NOTE]
> The rules collapse the pair- and tuple-keyed families onto one dimension, which is what makes a country, AS or port breakdown affordable to retain — [Recording rules](docs/README.md#recording-rules) carries what each group answers.

#### Alerting Rules Configuration Example

Add the rules from [`examples/prometheus_alert_rules.yml`](./examples/prometheus_alert_rules.yml) to your configuration.

### Grafana Dashboard

Import [`examples/grafana_xflow-exporter-dashboard.json`](./examples/grafana_xflow-exporter-dashboard.json), whose data source and devices are variables.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard.png">
  <img alt="Grafana dashboard showing flow volume, composition and exporter health panels" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard.png">
</picture>

> [!TIP]
> See [`docs/assets/xflow-exporter-dashboard_full.png`](https://github.com/umatare5/xflow-exporter/blob/main/docs/assets/xflow-exporter-dashboard_full.png) for the full capture image of the example.

> [!NOTE]
> Panels rank by packets rather than bytes, and the composition panels rank rather than total — [Dashboards](docs/README.md#dashboards) carries what each panel covers and why.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the `make` targets, the Docker build and the release process.

## Acknowledgement

I launched this project with the help of **Claude Code by Anthropic**, and I am grateful to the global developer community for their contributions to open source projects and public repositories.

## Licence

MIT. The binary statically links Apache-2.0, MIT, ISC and BSD 3-Clause dependencies, whose notices are reproduced in [`NOTICE`](NOTICE) and shipped alongside [`LICENSE`](LICENSE) in every release archive and container image.
