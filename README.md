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
> This project is under initial development. No release exists yet, and every interface below may change without notice.

## Protocol Support

| Protocol                        | Status  |
| :------------------------------ | :------ |
| NetFlow v5 (incl. J-Flow v5)    | Planned |
| NetFlow v8 (incl. J-Flow v8)    | Planned |
| NetFlow v9 (incl. FNF, J-Flow)  | Planned |
| IPFIX / NetFlow v10             | Planned |
| sFlow v5                        | Planned |

Transport is plaintext UDP. DTLS is not supported: no shipping network OS exports flows over DTLS, and Go has no production DTLS 1.3 implementation yet.

## Syntax

`xflow-exporter --help` prints every flag.

```bash
NAME:
   xflow-exporter - Prometheus exporter for NetFlow, IPFIX and sFlow

GLOBAL OPTIONS:
   --dry-run                    Validate configuration without starting the server
   --log.format string          Log format (json, text) (default: "json")
   --log.level string           Log level (debug, info, warn, error) (default: "info")
   --web.listen-address string  Address to bind the HTTP server to (default: "0.0.0.0")
   --web.listen-port int        Port number to bind the HTTP server to (default: 10040)
   --web.telemetry-path string  Path for the metrics endpoint (default: "/metrics")

   * Internal Collector Options

   --collector.internal.go-runtime  Enable Go runtime metrics collector
   --collector.internal.process     Enable process metrics collector

   * Receiver Options

   --receiver.address string [ --receiver.address string ]  Address to receive flow datagrams on (repeatable) (default: ":2055")
   --receiver.batch-size int                                Maximum datagrams read per kernel round trip (default: 64)
   --receiver.buffer-bytes int                              UDP socket receive buffer size in bytes (0 keeps the OS default) (default: 4194304)
   --receiver.max-packet-size int                           Largest datagram in bytes kept whole; larger ones are dropped (default: 9216)
   --receiver.queue-size int                                Datagrams buffered between the read loops and the decoders (default: 8192)
```

Every listener accepts every supported protocol, identified per datagram, so one port can carry NetFlow and IPFIX together and an sFlow deployment adds `--receiver.address :6343` rather than a mode switch. On Linux the read loops use `recvmmsg` batching; other platforms read one datagram per call, so performance figures are Linux figures.

## Endpoints

The exporter serves three endpoints:

- `/` — landing page, which confirms the exporter is running when reached at <http://localhost:10040/>
- `/metrics` — metrics endpoint, configurable via `--web.telemetry-path`
- `/healthz` — liveness probe, which returns a static 200 and deliberately ignores flow reception

## Metrics

### Exporter Health Metrics

These series describe the exporter itself. They have no module and no collector flag.

| Metric                                 | Type    | Description                                          |
| :------------------------------------- | :------ | :--------------------------------------------------- |
| `xflow_build_info`                     | Gauge   | Exporter version in the `version` label, always 1    |
| `xflow_receiver_packets_total`         | Counter | Datagrams received per `listener`, dropped included  |
| `xflow_receiver_bytes_total`           | Counter | Payload bytes received per `listener`                |
| `xflow_receiver_read_errors_total`     | Counter | Socket read failures per `listener`                  |
| `xflow_receiver_dropped_packets_total` | Counter | Drops per `listener` and `reason` before decoding    |
| `xflow_receiver_queue_length`          | Gauge   | Datagrams waiting between read loops and decoders    |
| `xflow_receiver_queue_capacity`        | Gauge   | Bound of that queue                                  |

`reason` is `queue_full` for a burst the queue could not absorb and `truncated` for a datagram larger than `--receiver.max-packet-size`. Both series are seeded at 0, so a first drop is a rise on a series that was already there.

The parsers and the aggregation metrics land in the upcoming milestones, each behind its own `--collector.*` flag and disabled by default. Until then received datagrams are counted, then discarded.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the `make` targets, the Docker build, the release process and how to open a pull request.

## Licence

[MIT](LICENSE). The binary statically links Apache-2.0, MIT and BSD 3-Clause dependencies, whose notices are reproduced in [NOTICE](NOTICE) and shipped alongside `LICENSE` in every release archive and container image.
