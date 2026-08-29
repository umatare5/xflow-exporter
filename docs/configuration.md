# Configuration

A verbatim `xflow-exporter --help` transcript: every flag and its default.

## Flags

```bash
NAME:
   xflow-exporter - Prometheus exporter for NetFlow, IPFIX and sFlow

USAGE:
   xflow-exporter [global options]

VERSION:
   0.1.0

GLOBAL OPTIONS:
   --dry-run                    Validate configuration without starting the server
   --help, -h                   show help
   --log.format string          Log format (json, text) (default: "json")
   --log.level string           Log level (debug, info, warn, error) (default: "info")
   --version, -v                print the version
   --web.listen-address string  Address to bind the HTTP server to (default: "0.0.0.0")
   --web.listen-port int        Port number to bind the HTTP server to (default: 10040)
   --web.telemetry-path string  Path for the metrics endpoint (default: "/metrics")

   # Collector Options

   --collector.applications   Enable application metrics from AVC, App-ID or applicationId
   --collector.asns           Enable AS pair metrics from device-exported AS numbers
   --collector.distributions  Enable flow size and duration native histograms
   --collector.exporters      Enable per-device traffic metrics
   --collector.hosts          Enable source-destination address pair metrics
   --collector.services       Enable address pair with protocol and port metrics

   * Aggregation Options

   --aggregation.entry-ttl duration  How long an idle aggregation entry keeps its series (default: 15m0s)
   --aggregation.max-entries int     Entry bound per aggregation table; new keys past it fold into other (default: 100000)
   --aggregation.min-bytes int       Bytes below which an entry folds into other at scrape time (0 publishes all) (default: 0)
   --aggregation.top-k int           Entries each table publishes as their own series; the rest fold into other (default: 1000)

   * Internal Collector Options

   --collector.internal.go-runtime  Enable Go runtime metrics collector
   --collector.internal.process     Enable process metrics collector

   * Parser Options

   --parser.max-fields-per-template int  Most fields one NetFlow v9 or IPFIX template may declare (default: 128)
   --parser.template-ttl duration        How long an unrefreshed template stays usable (default: 30m0s)

   * Receiver Options

   --receiver.address string [ --receiver.address string ]  Address to receive flow datagrams on (repeatable) (default: ":2055")
   --receiver.batch-size int                                Maximum datagrams read per kernel round trip (default: 64)
   --receiver.buffer-bytes int                              UDP socket receive buffer size in bytes (0 keeps the OS default) (default: 4194304)
   --receiver.max-packet-size int                           Largest datagram in bytes kept whole; larger ones are dropped (default: 9216)
   --receiver.queue-size int                                Datagrams buffered between the read loops and the decoders (default: 8192)
   --receiver.workers int                                   Decode workers consuming the queue (0 sizes to the CPU count) (default: 0)

```

## Notes

`--receiver.buffer-bytes` asks the kernel for that SO_RCVBUF; Linux clamps the grant to `net.core.rmem_max`, which this exporter cannot raise. Size it, and `--receiver.queue-size`, to absorb the export storms Flexible NetFlow emits after a cache flush.

A listener accepts every supported protocol, identified per datagram, so `--receiver.address` entries separate networks or ports rather than protocols.
