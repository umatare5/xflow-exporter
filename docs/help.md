# Help

The dump of `xflow-exporter --help`. It shows all available command-line options and their descriptions.

```text
NAME:
   xflow-exporter - Prometheus exporter for NetFlow, IPFIX and sFlow

USAGE:
   xflow-exporter [global options]

VERSION:
   0.11.0

GLOBAL OPTIONS:
   --dry-run                    Validate configuration without starting the server
   --help, -h                   show help
   --log.format string          Log format (json, text) (default: "json")
   --log.level string           Log level (debug, info, warn, error) (default: "info")
   --version, -v                print the version
   --web.enable-lifecycle       Enable /-/reload, which re-reads the enrichment sources
   --web.listen-address string  Address to bind the HTTP server to (default: "0.0.0.0")
   --web.listen-port int        Port number to bind the HTTP server to (default: 10053)
   --web.telemetry-path string  Path for the metrics endpoint (default: "/metrics")

   # Collector Options

   --collector.applications   Enable application metrics from AVC, App-ID, applicationId or --enrich.services
   --collector.asns           Enable AS pair metrics, from device-exported numbers or --enrich.asn-database
   --collector.countries      Enable country pair metrics, which need --enrich.country-database
   --collector.destinations   Enable destination address with protocol and port metrics
   --collector.distributions  Enable flow size and duration native histograms
   --collector.dscp           Enable DSCP class metrics, from the TOS byte or the exported code point
   --collector.exporters      Enable per-device traffic metrics
   --collector.hosts          Enable source-destination address pair metrics
   --collector.services       Enable address pair with protocol and port metrics
   --collector.tcp-flags      Enable TCP control-bit profile metrics
   --collector.threats        Enable flagged address metrics, which need --enrich.threat-file
   --collector.vlans          Enable VLAN pair metrics, which need vlans in --enrich.mapping-file

   # Enrichment Options

   --enrich.asn-database string                                 Path to a MaxMind-format ASN database, filling the AS numbers a device omits
   --enrich.country-database string                             Path to a MaxMind-format country database, filling the ISO codes for --collector.countries
   --enrich.mapping-file string                                 Path to a YAML file naming devices, their interfaces, VLANs and extra transport ports
   --enrich.services                                            Name the application from the transport port where the device named none
   --enrich.threat-file string [ --enrich.threat-file string ]  Path to a file of flagged addresses, one per line (repeatable)

   * Aggregation Options

   --aggregation.entry-ttl duration  How long an idle aggregation entry keeps its series (default: 15m0s)
   --aggregation.max-entries int     Entry bound per aggregation table, folding new keys into other past it (default: 100000)
   --aggregation.min-bytes int       Bytes below which an entry is withheld at scrape time (0 publishes all) (default: 0)
   --aggregation.top-k int           Entries each table publishes as their own series, the rest withheld (default: 1000)

   * Internal Collector Options

   --collector.internal.go-runtime  Enable Go runtime metrics collector
   --collector.internal.process     Enable process metrics collector

   * Parser Options

   --parser.max-fields-per-template int  Most fields one NetFlow v9 or IPFIX template may declare (default: 128)
   --parser.template-ttl duration        How long an unrefreshed template, domain or sampler is held (default: 30m0s)

   * Receiver Options

   --receiver.address string [ --receiver.address string ]  Address to receive flow datagrams on (repeatable) (default: ":4739")
   --receiver.batch-size int                                Maximum datagrams read per kernel round trip (default: 64)
   --receiver.buffer-bytes int                              UDP socket receive buffer size in bytes (0 keeps the OS default) (default: 4194304)
   --receiver.max-packet-size int                           Largest datagram in bytes kept whole, dropping larger ones (default: 9216)
   --receiver.queue-size int                                Datagrams buffered between the read loops and the decoders (default: 8192)
   --receiver.workers int                                   Decode workers, each device hashed to one of them (0 sizes to GOMAXPROCS) (default: 0)

   * Remote Write Options [Experimental]

   --remote-write.header string [ --remote-write.header string ]  Extra request header as name=value (repeatable)
   --remote-write.interval duration                               How often the registry is shipped (default: 1m0s)
   --remote-write.password string                                 Basic auth password for the endpoint [$XFLOW_REMOTE_WRITE_PASSWORD]
   --remote-write.timeout duration                                Timeout of one write (default: 30s)
   --remote-write.url string                                      Remote Write 2.0 endpoint to ship metrics to, which enables the client when set
   --remote-write.username string                                 Basic auth username for the endpoint [$XFLOW_REMOTE_WRITE_USERNAME]
```

## Technical Notes

This section covers technical considerations and best practices for development, configuration, and operation.

**Socket Buffer Tuning**: `--receiver.buffer-bytes` sets `SO_RCVBUF`, clamped by `net.core.rmem_max`. Tune both this and `--receiver.queue-size` to absorb burst cache flushes.

**Worker Allocation**: Ingest workers hash by exporter IP. Setting `--receiver.workers` beyond total active devices provides no concurrency benefit.

**Protocol Multiplexing**: Listeners ingest all supported protocols on the same socket. Dedicate one listener per device stream to prevent packet reordering across threads.

**Dry-Run Validation**: `--dry-run` validates flags and verifies readability of `--enrich.*` files without binding UDP/HTTP ports or testing remote endpoints.

**Credential Precedence**: `--remote-write.*` CLI flags override `XFLOW_REMOTE_WRITE_*` environment variables. Prefer environment variables to prevent leaking credentials into the OS process table.
