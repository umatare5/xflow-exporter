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
| `--enrich.threat-file`      | A flag on addresses a list file names    |

A database path that cannot be opened fails startup rather than enriching
nothing in silence. Neither database ships with this exporter: point the
flags at a GeoLite2 or DB-IP file you already hold. Database lookups are
local, so no address leaves the host.

Nothing here reaches a network. The exporter reads files and never fetches
them, so no address ever leaves the host and no credential is configured.

### Threat lists

`--enrich.threat-file` reads a file of flagged addresses, one per line, and
is repeatable so several published lists combine into one set.

- **Fetching is not the exporter's job.** `scripts/fetch-threat-lists.sh`
  downloads the published lists, merges and deduplicates them, and writes one
  file. Run it from cron and reload afterwards, the same shape the MaxMind
  databases are already kept in.
- **Format** — one address per line. Blank lines, `#` and `;` comments, and
  any trailing field after whitespace or a comma are skipped, so a CSV export
  loads without a converter. A line that is not an address is skipped rather
  than failing the file: one malformed row must not cost the rest.
- **An unlisted address is not a clean one.** It is an address no list
  covers, which is absence rather than a finding.
- **Both directions are covered.** Most lists name the origins of inbound
  attacks, and a hit lands on `direction="src"`. One names malicious
  destinations — command-and-control, malware drops and phishing hosts — and
  a hit there lands on `direction="dst"`, which reads as an inside host that
  reached one of them.
- **A prefix is not an address.** A `198.51.100.0/24` line is skipped like any
  other line that is not an address, so a list published in CIDR notation
  loads only its bare addresses. `xflow_threat_skipped_lines` counts what a
  load passed over, and a reload logs the count, so the gap is visible rather
  than read as full coverage. Blank lines and comments are not counted.
- **The licence of a list is the operator's to check.** Several published
  aggregates carry a non-commercial clause inherited from an upstream feed.
  The lists the script fetches are MIT and CC0.
- **Size** — the lists the script fetches combine to roughly 420,000
  addresses, which costs about 20 MiB and answers a lookup in tens of
  nanoseconds.

### Reloading

`--web.enable-lifecycle` exposes `/-/reload`, which re-reads every enrichment
source from disk. A `SIGHUP` does the same and needs no flag. Both are the
spelling Prometheus uses.

- **Off by default** — the endpoint is a write, so it stays unexposed unless
  asked for, and it carries no authentication of its own. Keep it behind the
  same controlled path as the metrics.
- **POST or PUT only.** A reload changes what the process holds, so a GET
  does not trigger one.
- **A failed reload keeps the previous data.** A list that has gone missing
  would otherwise unflag every address at once, which reads as a network that
  had just gone clean. `xflow_threat_reload_failures_total` counts those.
- **Atomic** — the new set is built whole before it replaces the old one, so
  a lookup never sees a half-loaded set and the decode path never pauses.

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
