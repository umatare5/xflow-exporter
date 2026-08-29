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

| Protocol                        | Status    |
| :------------------------------ | :-------- |
| NetFlow v5 (incl. J-Flow v5)    | Supported |
| NetFlow v8 (incl. J-Flow v8)    | Supported |
| NetFlow v9 (incl. FNF, J-Flow)  | Supported |
| IPFIX / NetFlow v10             | Supported |
| sFlow v5                        | Planned   |

NetFlow v8 covers all fourteen aggregation methods of aggregation export version 2. A v8 record is pre-aggregated on the router, so it carries only its method's dimensions and the rest stay absent.

NetFlow v9 and IPFIX templates are cached per exporter address and Observation Domain ID together, as RFC 7011 requires, so two domains reusing one template ID never corrupt each other. A template is refused when it declares a zero-width fixed field or more than `--parser.max-fields-per-template` fields, and expires after `--parser.template-ttl` without a re-announcement. IPFIX adds enterprise information elements, variable-length fields with strict bounds checking, and template withdrawals.

Options templates feed the packet sampling rate — the PSAMP interval/space pair, the random-sampler interval, or the legacy interval, in that order — which is stamped onto decoded records and published as `xflow_sampling_rate`. Cisco AVC application tables announced through options resolve the `applicationId` (IE 95) of each record into the name and category the device itself declared, and PAN-OS App-ID and User-ID strings are carried through a string interner so one name allocates once rather than per flow.

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
   --receiver.workers int                                   Decode workers consuming the queue (0 sizes to the CPU count) (default: 0)

   * Parser Options

   --parser.max-fields-per-template int  Most fields one NetFlow v9 or IPFIX template may declare (default: 128)
   --parser.template-ttl duration        How long an unrefreshed template stays usable (default: 30m0s)
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
| `xflow_flows_total`                    | Counter | Records decoded per `exporter` and `version`         |
| `xflow_decode_errors_total`            | Counter | Rejections per `exporter`, `version` and `reason`    |
| `xflow_last_flow_timestamp_seconds`    | Gauge   | Unix time of the exporter's last decoded datagram    |
| `xflow_templates`                      | Gauge   | Unexpired templates per `exporter`, `odid`, `type`   |
| `xflow_sequence_missed_total`          | Counter | Export packets lost per `exporter` and `odid`        |
| `xflow_sampling_rate`                  | Gauge   | Declared sampling rate, absent until one arrives     |

On `xflow_receiver_dropped_packets_total`, `reason` is `queue_full` for a burst the queue could not absorb and `truncated` for a datagram larger than `--receiver.max-packet-size`. Both series are seeded at 0, so a first drop is a rise on a series that was already there.

On `xflow_decode_errors_total`, `reason` is `unsupported_version` for a datagram no decoder claims, `malformed` for one whose claimed structure does not fit its bytes, and `unsupported_aggregation` for a NetFlow v8 aggregation method outside the fourteen this exporter knows. The template protocols add `missing_template`, expected after a restart until each device re-announces; `invalid_template` for an announcement the limits refuse; and `reserved_set` for a flowset in the reserved 2-255 range. Exporter-labeled series appear on a device's first datagram: a push protocol cannot know its senders in advance.

Alert on freshness with `time() - xflow_last_flow_timestamp_seconds`: a device that goes silent stops moving its timestamp while every counter freezes, and nothing else can tell that from a healthy quiet network.

The aggregation metrics land in the upcoming milestones, each behind its own `--collector.*` flag and disabled by default. Until then decoded records are counted, then discarded.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the `make` targets, the Docker build, the release process and how to open a pull request.

## Licence

[MIT](LICENSE). The binary statically links Apache-2.0, MIT and BSD 3-Clause dependencies, whose notices are reproduced in [NOTICE](NOTICE) and shipped alongside `LICENSE` in every release archive and container image.
