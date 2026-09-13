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

xflow-exporter receives flow datagrams from networking devices and exposes them as Prometheus metrics.

- ⚙️ **Unifies Workflow**: Bundles collection, aggregation, and enrichment features into a single exporter
- 🧮 **In-Memory Aggregation**: Summarizes bounded-cardinality tables with Top-K and idle eviction
- 🏷️ **Metadata Enrichment**: Labels apps, ASNs, countries, threats, and VLANs from local files
- 📊 **Native Histograms**: Yields size and duration quantiles with high accuracy (Prometheus v3.8+)

## Architecture

Networking devices push flow datagrams into the exporter, and Prometheus pulls aggregates out of it.

<picture>
  <img alt="Devices push flow datagrams into the exporter, and Prometheus pulls aggregates out of it" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/readme_architecture.png" width="705px">
</picture>

This architecture is **suitable for lightweight traffic analysis** in enterprise and small-to-medium data center environments with minimal resource and cost requirements, **but not for heavy traffic analysis** in large-scale data centers, clouds, ISPs, or security domains.

> [!NOTE]
> Scrapes read in-memory tables asynchronously, never waiting on flow arrival. See [Push and Pull](docs/architecture.md#push-and-pull) for the details.

## Supported Protocols

**NetFlow v5, v8, v9, IPFIX and sFlow v5.** See [Protocols](docs/protocols.md) for wire formats and devices each decoder was read on.

## Quick Start

### 1. Send flow records from the networking devices

Export flows to the xflow-exporter's `4739/udp` — the default IANA registered port for IPFIX.

For example, on **Cisco C2960CX** and **Netflow v9**, use the following configuration to export flows:

```bash
# 1. Create minimum set of flow records
flow record MINIMAL_FLOW_RECORDS_IPV4
  match ipv4 tos                       # For DSCP
  match ipv4 protocol                  # For the protocol type - 6: TCP, 17: UDP
  match ipv4 source address            # Required: Source IP address of the flow
  match ipv4 destination address       # Required: Destination IP address of the flow
  match transport source-port          # Required: Source port of the flow
  match transport destination-port     # Required: Destination port of the flow
  collect transport tcp flags          # Collect TCP flags
  collect interface input              # Collect input interface
  collect flow sampler                 # Collect flow sampler information
  collect counter bytes long           # Collect byte count of the flow
  collect counter packets long         # Collect packet count of the flow

# 2. Configure the flow exporter
flow exporter XFLOW-EXPORTER
  destination 192.0.2.1               # IP address of xflow-exporter
  transport udp 4739                  # Listen port of xflow-exporter
  source Vlan100                      # Source interface for the flow exporter
  template data timeout 60            # Timeout for the template data in seconds
  option sampler-table timeout 60     # Timeout for the sampler table in seconds

# 3. Set up the flow monitor
flow monitor EXAMPLE_FLOW_MONITOR
  exporter XFLOW-EXPORTER
  record MINIMAL_FLOW_RECORDS_IPV4

# 4. Create the sampler
sampler MINIMAL_RESOLUTION_SAMPLER
  mode random 1 out-of 1022            # Window size to select packets from. On C2960CX, the range is <32-1022>.

# 5. Apply the sampler to the interface
interface GigabitEthernet0/1
  ip flow monitor EXAMPLE_FLOW_MONITOR sampler MINIMAL_RESOLUTION_SAMPLER input

# 6. Verify the configuration and flow records
show flow monitor EXAMPLE_FLOW_MONITOR

# TIP: With the "cache" argument, the command displays the detailed flow records.
# show flow monitor EXAMPLE_FLOW_MONITOR cache
```

> [!TIP]
> All protocols reach that same port. See [Version Identification](docs/protocols.md#version-identification) for how a datagram is detected.

### 2. Run the exporter and start receiving flow records

Run the exporter using Docker as shown below, and start to receive the flow records.

```bash
docker run -p 10053:10053 -p 4739:4739/udp ghcr.io/umatare5/xflow-exporter:latest
```

> [!TIP]
> See [Releases](https://github.com/umatare5/xflow-exporter/releases) for OS-specific binaries. `(linux|darwin)_(amd64|arm64)` and `windows_amd64` are supported.

### 3. Scrape it

```bash
curl http://localhost:10053/metrics
```

> [!TIP]
> See [Metrics](#metrics) for available metrics, and [Prometheus Configuration](#prometheus-configuration) for the job and the alerting rules.

## Collectors

This exporter supports multiple collectors. See [Enrichment](docs/enrichment.md) for the details.

| Collector     | Flag                        | Exposes                                  |
| :------------ | :-------------------------- | :--------------------------------------- |
| Applications  | `--collector.applications`  | Traffic per application                  |
| BGP AS        | `--collector.asns`          | Traffic per AS pair                      |
| Countries     | `--collector.countries`     | Traffic per country pair                 |
| Destinations  | `--collector.destinations`  | Traffic per destination, protocol, port  |
| Distributions | `--collector.distributions` | Flow size and duration native histograms |
| DSCP          | `--collector.dscp`          | Traffic per DSCP class                   |
| Exporter      | `--collector.exporters`     | Traffic per observation domain           |
| Hosts         | `--collector.hosts`         | Traffic per source-destination pair      |
| Services      | `--collector.services`      | Traffic per address pair, protocol, port |
| TCP Flags     | `--collector.tcp-flags`     | Traffic per TCP control-bit profile      |
| Threats       | `--collector.threats`       | Traffic per flagged address              |
| VLANs         | `--collector.vlans`         | Traffic per VLAN pair                    |

> [!IMPORTANT]
> All collectors are **disabled by default** to bound cardinality, and `--collector.distributions` needs Prometheus v3.8+ with native histogram ingestion enabled in the scrape configuration. Applications, BGP AS, Countries, Threats and VLANs each draw on an `--enrich.*` source.

## Flags

`xflow-exporter --help` prints full flags. See [Help](docs/help.md) for the details.

| Flag               | Description                                                                                                           |
| :----------------- | :-------------------------------------------------------------------------------------------------------------------- |
| `--aggregation.*`  | For controlling how flow records are combined and published. See [Push and Pull](docs/architecture.md#push-and-pull). |
| `--enrich.*`       | For filling missing labels from local files. See [Enrichment](docs/enrichment.md).                                    |
| `--parser.*`       | For NetFlow v9 and IPFIX templates. See [Decoder](docs/architecture.md#decoder).                                      |
| `--receiver.*`     | For incoming flow datagrams. See [Push and Pull](docs/architecture.md#push-and-pull).                                 |
| `--remote-write.*` | For shipping the registry to a Remote Write 2.0 endpoint. See [Remote Write](SECURITY.md#remote-write).               |

## Endpoints

The exporter serves these endpoints. See [Endpoints](docs/architecture.md#endpoints) for the details, and [Sources](docs/enrichment.md#sources) for what a reload does.

| Path        | Detail                                                                         |
| :---------- | :----------------------------------------------------------------------------- |
| `/`         | Landing page – confirming the exporter is up at <http://localhost:10053/>      |
| `/metrics`  | Metrics endpoint – set via `--web.telemetry-path`                              |
| `/healthz`  | Liveness endpoint – returns static 200 and deliberately ignores flow data      |
| `/-/reload` | Reload endpoint – re-reads sources on POST/PUT, needs `--web.enable-lifecycle` |

## Metrics

This exporter exposes metrics for various aspects of network traffic.

| Page                                  | Covers                                                        |
| :------------------------------------ | :------------------------------------------------------------ |
| **[Collectors](docs/collectors.md)**  | The twelve collectors, their metrics and their labels         |
| **[Exporter health](docs/health.md)** | Reception, decoding, aggregation, enrichment and remote write |

### Collector Metrics

The following table summarizes the popular metrics of this collector. See [`docs/collectors.md`](docs/collectors.md) for the full list.

| Collector     | Metric                          | Type      | Description            |
| :------------ | :------------------------------ | :-------- | :--------------------- |
| Exporter      | `xflow_exporter_bytes_total`    | Counter   | Traffic per domain     |
| Hosts         | `xflow_host_pair_bytes_total`   | Counter   | Top talkers            |
| Services      | `xflow_service_bytes_total`     | Counter   | Top conversations      |
| Applications  | `xflow_application_bytes_total` | Counter   | Traffic by application |
| Distributions | `xflow_flow_bytes`              | Histogram | Flow size distribution |

### Exporter Health Metrics

The following table summarizes the health metrics of the exporter itself. See [`docs/health.md`](docs/health.md) for the full list.

| Metric                                 | Type    | Description                            |
| :------------------------------------- | :------ | :------------------------------------- |
| `xflow_flows_total`                    | Counter | Records decoded per device and version |
| `xflow_decode_errors_total`            | Counter | Rejections per device and reason       |
| `xflow_last_flow_timestamp_seconds`    | Gauge   | Unix time of the last record           |
| `xflow_receiver_dropped_packets_total` | Counter | Pre-decode drops per listener          |
| `xflow_sampling_rate`                  | Gauge   | Rate in force per domain               |
| `xflow_aggregation_entries`            | Gauge   | Entries held per collector             |

## Examples

### Exporter Configuration

With no collector enabled the receiver counts every datagram and publishes no traffic series:

```bash
$ ./xflow-exporter --log.format text
time=2026-08-26T19:58:24.288+09:00 level=INFO msg="Starting xflow-exporter" version=0.1.0 listen_address=0.0.0.0 listen_port=10053 telemetry_path=/metrics
time=2026-08-26T19:58:24.291+09:00 level=INFO msg="Flow receiver listening" listener=:4739
time=2026-08-26T19:58:24.292+09:00 level=INFO msg="HTTP server listening" addr=0.0.0.0:10053
```

The three collectors usually start from:

```bash
./xflow-exporter --collector.exporters --collector.hosts --collector.services
```

> [!NOTE]
> See [`.air.toml`](https://github.com/umatare5/xflow-exporter/blob/main/.air.toml) for the complete configuration, which enables every collector.

### Prometheus Configuration

There are several Prometheus configuration examples provided below:

- **Job:** [`examples/prometheus.yml`](./examples/prometheus.yml)
- **Recording Rules:** [`examples/prometheus_record_rules.yml`](./examples/prometheus_record_rules.yml)
- **Alerting Rules:** [`examples/prometheus_alert_rules.yml`](./examples/prometheus_alert_rules.yml)

### Grafana Configuration

Import [`examples/grafana_xflow-exporter-dashboard.json`](./examples/grafana_xflow-exporter-dashboard.json). See [`docs/collectors.md`](docs/collectors.md) for the panels and the metrics.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard.png">
  <img alt="Grafana dashboard showing flow volume, composition and exporter health panels" src="https://raw.githubusercontent.com/umatare5/xflow-exporter/main/docs/assets/xflow-exporter-dashboard.png">
</picture>

> [!TIP]
> See [`docs/assets/xflow-exporter-dashboard_full.png`](https://github.com/umatare5/xflow-exporter/blob/main/docs/assets/xflow-exporter-dashboard_full.png) for the full capture image of the example.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development, the tests, the documentation conventions and the release process.

## License

MIT. The binary statically links Apache-2.0, MIT, ISC and BSD 3-Clause dependencies, whose notices are reproduced in [`NOTICE`](NOTICE) and shipped alongside [`LICENSE`](LICENSE) in every release archive and container image.
