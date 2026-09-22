# Help

The dump of `xflow-exporter --help`. It shows all available command-line options and their descriptions.

```text
NAME:
   xflow-exporter - Prometheus exporter for NetFlow, IPFIX and sFlow

USAGE:
   xflow-exporter [global options]

VERSION:
   0.12.0

GLOBAL OPTIONS:
   --dry-run                         Validate configuration without starting the server
   --help, -h                        show help
   --log.format string               Log format (json, text) (default: "json")
   --log.level string                Log level (debug, info, warn, error) (default: "info")
   --version, -v                     print the version
   --web.enable-aggregation-entries  Enable /entries, which lists every entry the aggregation tables hold
   --web.enable-lifecycle            Enable /-/reload, which re-reads the enrichment sources
   --web.listen-address string       Address to bind the HTTP server to (default: "0.0.0.0")
   --web.listen-port int             Port number to bind the HTTP server to (default: 10053)
   --web.telemetry-path string       Path for the metrics endpoint (default: "/metrics")

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

## Flags

The flags divide into a few families. These notes carry only what the transcript cannot.

### --dry-run

It validates the flags and reads every `--enrich.*` file. It binds no UDP or HTTP port and contacts no remote endpoint, so a dry run passes against a configuration already in service.

### --receiver.buffer-bytes and --receiver.queue-size

The first sets `SO_RCVBUF`, which `net.core.rmem_max` clamps. Size both against a cache flush rather than the average rate – [Scrape Path](architecture.md#scrape-path) carries why a full queue drops for every device on the listener.

### --receiver.workers

Each device hashes to one worker, so a count above the active device total leaves the extra workers idle. Zero sizes the pool to `GOMAXPROCS`.

### --receiver.address

The flag repeats, and every listener reads all five protocols on its own socket. One listener per device stream keeps a burst from one device off the others.

### --remote-write.username and --remote-write.password

The flag wins over `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD`.

> [!IMPORTANT]
> Pass the credential in the environment. A flag puts it in the process table, where `ps` shows it to every account on the host.

## Technical Notes

The transcript above prints a default rather than an effect, and these hold across the flags rather than for one.

**Unstamped builds**: The `VERSION:` line reads `dev` unless the build stamped it, so a transcript taken from `go build` contradicts the release it ships with. `make build` stamps it.

**Flag order**: No flag depends on its position, and a repeated non-repeatable flag takes the last value rather than failing.
