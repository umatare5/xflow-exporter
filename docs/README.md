# Documentation

Reference pages for xflow-exporter. The [README](../README.md) covers getting flows received and scraped, and these pages carry the full metric catalogue and the behaviour every module shares.

| Page                              | Focus                                  |
| :-------------------------------- | :------------------------------------- |
| [Protocols](protocols.md)         | Per-protocol behaviour and limits      |
| [Collectors](collectors.md)       | Every metric family and its labels     |
| [Configuration](configuration.md) | Flags and defaults, as `--help` prints |

## Technical Information

### Push and pull

Flow export is push, Prometheus is pull, and this exporter bridges the two. The [README](../README.md#architecture) carries the architecture diagram.

- **Scrapes never wait** — a scrape reads the aggregation tables as they are, while flow datagrams keep accumulating between scrapes.
- **No target to probe** — there is no `up`-style reachability toward a push sender, so per-device freshness is `xflow_last_flow_timestamp_seconds` instead.
- **Naming** — RFC 7011 calls the device the "exporter", and the `exporter` label follows that reading: it always names the device.

### Absence

A dimension a flow record did not carry produces no series: never `0`, `false` or an epoch timestamp. Prometheus cannot distinguish a fabricated zero from a measured one.

- **Ingest** — a record without addresses feeds no host or service entry, one without an application feeds no application entry, and a NetFlow v8 aggregate feeds only the tables its method's dimensions cover.
- **Eviction** — an aggregation entry idle past `--aggregation.entry-ttl` is removed and its series disappears. A flow nobody has seen is gone, not zero.
- **Freshness** — `xflow_last_flow_timestamp_seconds` exists only once a device's datagram has decoded, and `xflow_sampling_rate` only once a rate has arrived.

### Counter semantics

The table families are counters accumulated since each entry was created, and an entry evicted then re-created restarts from zero.

- **Ranges** — give `rate()` a range that spans several scrapes. The staleness marker Prometheus writes at eviction separates the old series from a rebirth.
- **Folding** — the `other` series of each family is seeded at zero and absorbs what the entry bound rejected at ingest and what eviction took away, so it only ever rises. The live tail below the Top-K cut is withheld rather than summed into it: those totals are still moving, and adding them per scrape would make the counter fall whenever one entry is evicted or grows into the cut.
- **Flow counts** — `_flows_total` is as exported: a packet-sampling protocol observes flows rather than counting them, so no sampling multiplication is applied to it.

### Sampling correction

`_bytes_total` and `_packets_total` are multiplied by the sampling rate in force when the record was decoded.

- **Sources** — the v5 header interval, the v9/IPFIX options (PSAMP interval and space pair first, then the random-sampler interval, then the plain interval), and the per-sample rate sFlow carries inline.
- **Audit** — `xflow_sampling_rate` publishes the rate each observation domain declared, so a corrected series can be traced to the rate that scaled it.
- **Unsampled** — a record carrying no rate multiplies by one, and PAN-OS NetFlow is always unsampled.

### Enrichment

An enrichment source fills a dimension the exporting device did not carry.
Every source is off by default and enabled per `--enrich.*` flag.

- **Never overwrites** — the device saw the packet and this exporter did not,
  so an exported reading is the authority and enrichment fills absence alone.
  That is what keeps an enriched series comparable with an unenriched one.
- **Feeds the existing families** — a filled dimension keys the module that
  already publishes it, so naming an application from its port populates
  `xflow_application_*` rather than a family of its own.
- **Cardinality** — a filled dimension creates series that were previously
  absent, which is why each source is a deliberate opt-in.
- **Observability** — `xflow_enrichment_lookups_total` reports what each
  source made of the records it saw: `filled`, `unknown` where it knew
  nothing, `skipped` where the device had already carried the dimension.

The sources are these.

| Flag                        | Fills                                    |
| :-------------------------- | :--------------------------------------- |
| `--enrich.services`         | The application, from the transport port |
| `--enrich.asn-database`     | The AS numbers, from a MaxMind-format DB |
| `--enrich.country-database` | The ISO country codes, from the same     |
| `--enrich.threat-api-key`   | A flag on addresses AbuseIPDB reports    |

A database path that cannot be opened fails startup rather than enriching
nothing in silence. Neither database ships with this exporter: point the
flags at a GeoLite2 or DB-IP file you already hold. Database lookups are
local, so no address leaves the host.

The reputation source is the exception, and the only part of this exporter
that talks to anyone.

- **It sends addresses to AbuseIPDB.** Setting `--enrich.threat-api-key`, or
  `XFLOW_THREAT_API_KEY`, is what turns that on. Without a key nothing is
  sent and nothing is flagged.
- **Only public addresses go out.** Anything the monitored network assigns
  itself — RFC 1918, loopback, link-local, multicast, unique-local — is never
  sent: the service holds nothing on it, and shipping it would leak the
  network's internal structure for no answer in return.
- **Lookups are asynchronous.** A record is flagged from the cache alone and
  a miss queues the address, so a third party's latency never reaches the
  decode path where a slow answer costs datagrams.
- **Verdicts are cached and bounded**, for `--enrich.threat-cache-ttl` and up
  to `--enrich.threat-cache-size`. A failed lookup is cached too, so a
  service that is down costs one request per address per TTL.
- **An unflagged address is not a clean one.** It is an address no verdict
  covers yet, which is absence rather than a finding.

### Remote write

`--remote-write.url` ships the exporter's own registry to a Remote Write 2.0
endpoint, for the deployments a Prometheus scrape cannot reach. It is off
until a URL is set.

- **A second reader, not a second source** — the writer gathers the same
  registry a scrape gathers, so enabling it changes no series and no value.
  Scraping and shipping at once simply delivers the same data twice.
- **Resolution** — one gather per `--remote-write.interval`, which is what
  the remote endpoint sees. It plays the part a scrape interval plays.
- **Native histograms are not shipped.** Remote Write 2.0 carries them as
  their own message, and reducing one to a single sample would be a value
  nobody measured. `--collector.distributions` therefore reaches a scrape
  but not a remote endpoint.
- **Credentials** — basic auth from `--remote-write.username` and
  `--remote-write.password`, which also read `XFLOW_REMOTE_WRITE_USERNAME`
  and `XFLOW_REMOTE_WRITE_PASSWORD`, plus any `--remote-write.header`.
- **Observability** — `xflow_remote_write_*` reports accepted writes, failed
  ones, series shipped, and the instant of the last success, which is absent
  until one succeeds.

### Bounded state

Every map keyed by data the wire controls carries a bound, because a push
protocol cannot choose its senders.

- **Observation domains** — the identifier is a wire field, so each device may
  open at most 256 of them. A refusal counts `domain_limit` against that
  device and raises `xflow_domains_refused_total`.
- **Idle domains** — swept on the template TTL, which returns the slot to the
  device's budget and keeps the domain count following the fleet.
- **Vendor strings** — the interner holds at most 65536. Past the bound a
  value is copied per occurrence, which costs an allocation and never a wrong
  reading.

Maps keyed by the source address alone — the decode statistics, the
application tables, the distribution histograms — are bounded by restricting
the receiver to permitted senders. See [SECURITY.md](../SECURITY.md).

### Templates

NetFlow v9 and IPFIX data decode against templates cached per exporter address and Observation Domain ID together, per RFC 7011.

- **Startup** — `missing_template` rejections are expected after a restart until each device re-announces. A device that never does keeps the counter rising, which is the signal to check its template refresh configuration.
- **Limits** — a template with a zero-width fixed field, more than `--parser.max-fields-per-template` fields, or specifiers that overrun their set is refused as `invalid_template`.
- **Expiry** — a template unrefreshed for `--parser.template-ttl` stops serving: an orphaned template may describe a schema the device has replaced.

### Packet sections

A NetFlow-Lite record carries one sampled packet section instead of parsed flow fields, and decodes through the header walk the sFlow decoder uses.

- **Elements** — the v9 mode's deprecated field 104 (layer2packetSectionData, the measured device behaviour), and IPFIX `dataLinkFrameSection` (315), `ipHeaderPacketSection` (313) and `dataLinkFrameSize` (312).
- **Precedence** — fields the device parsed itself win: the section fills only what is still absent, and one record reads as one sampled packet.
- **Padding** — a fixed-size v9 section is zero-padded, so a frame cut before its transport header reads zero ports from the padding — the one ambiguity a padded section cannot escape.

### Native histograms

`--collector.distributions` publishes `xflow_flow_bytes` and `xflow_flow_duration_seconds` as native histograms, one series per exporter with exponential buckets.

- **Scraping** — Prometheus v3.8+ with native histogram ingestion enabled in the scrape configuration. The classic text exposition carries only `_count` and `_sum`.
- **Duration** — observed only where the record carried both flow instants: sFlow samples and clock-less templates contribute size but no duration.
