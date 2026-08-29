# Documentation

Reference pages for xflow-exporter. The [README](../README.md) covers getting flows received and scraped; these pages carry the catalogues and the behaviour every module shares.

| Page                              | Focus                                  |
| :-------------------------------- | :------------------------------------- |
| [Protocols](protocols.md)         | Per-protocol behaviour and limits      |
| [Collectors](collectors.md)       | The traffic modules and their labels   |
| [Health](health.md)               | The exporter's own metrics and reasons |
| [Configuration](configuration.md) | Flags and defaults, as `--help` prints |

## Technical Information

### Push and pull

- **Scrapes never wait** — a scrape reads the aggregation tables as they stand, so its latency is independent of flow arrival.
- **No target to probe** — nothing answers an `up`-style reachability check toward a push sender, so per-device liveness is `xflow_last_flow_timestamp_seconds`.
- **Naming** — RFC 7011 calls the device the exporter, and the `exporter` label follows it: it names the device, never this binary.
- **Tuning** — `--receiver.*`, `--parser.*` and `--aggregation.*` bound the receive path. Linux read loops batch with `recvmmsg`; elsewhere it is one datagram per call.

### Absence

A dimension the record did not carry produces no series — never `0`, `false` or an epoch instant.

- **Ingest** — a record without addresses feeds no host or service entry, one without an application feeds no application entry, and a NetFlow v8 aggregate feeds only the tables its method's dimensions cover.
- **Eviction** — an entry idle past `--aggregation.entry-ttl` is removed and its series disappears.
- **Freshness** — `xflow_last_flow_timestamp_seconds` appears once a device's datagram has decoded, `xflow_sampling_rate` once a rate has arrived.

### Counter semantics

Table families accumulate from entry creation, and an entry evicted then re-created restarts at zero.

- **Rebirth** — the staleness marker Prometheus writes at eviction separates the old series from the new one.
- **Folding** — the `other` series absorbs what `--aggregation.max-entries` rejected at ingest and nothing else.
- **Not folded** — the tail below the Top-K cut is still accumulating, so summing it would make the counter fall whenever an entry is evicted or rises into the cut; an evicted entry's totals are not folded in either, those bytes having already reached Prometheus on the entry's own series, where folding them again would make `sum(rate())` over the family read twice what was ingested.
- **Flow counts** — `_flows_total` is as exported, a packet-sampling protocol observing flows rather than counting them.

### Sampling correction

`_bytes_total` and `_packets_total` carry the record's value multiplied by the rate in force at decode.

- **Sources** — the v5 header interval, the v9/IPFIX options rates in the precedence [Protocols](protocols.md#options-and-enrichment) tabulates, and sFlow's per-sample inline rate.
- **Audit** — `xflow_sampling_rate` publishes what a v9 or IPFIX domain declared through its options; the v5 and sFlow rates ride the records and publish no series.
- **Unsampled** — a record carrying no rate multiplies by one, and PAN-OS NetFlow is always unsampled.

### Enrichment

An `--enrich.*` source fills a dimension the device did not carry. Every source is off by default.

| Flag                        | Fills                                    |
| :-------------------------- | :--------------------------------------- |
| `--enrich.services`         | The application, from the transport port |
| `--enrich.asn-database`     | The AS numbers, from a MaxMind-format DB |
| `--enrich.country-database` | The ISO country codes, from the same     |
| `--enrich.threat-file`      | A flag on addresses a list file names    |

- **Never overwrites** — an exported reading wins, which is what keeps an enriched series comparable with an unenriched one.
- **Feeds the existing families** — a filled dimension keys the module that already publishes it, so naming an application from its port populates `xflow_application_*`.
- **Cardinality** — a filled dimension creates series that were absent, which is why each source is a deliberate opt-in.
- **Observability** — `xflow_enrichment_lookups_total` reports the `result` split [Health](health.md#labels) catalogues.

Lookups are local: nothing is fetched and no credential is held. Neither database ships here — point the flag at a GeoLite2 or DB-IP file, or run `scripts/fetch-enrichment-data.sh databases`. A path that cannot be opened fails startup rather than enriching nothing in silence.

A country is where the database registers the prefix, not where the traffic went: a lab in Japan reaching Cloudflare over AS 13335 measured `src_country="CA"`. Read `xflow_country_pair_*` that way, and do not reconcile it with a transit bill.

### Threat lists

`--enrich.threat-file` reads flagged addresses, one per line, and is repeatable so several published lists combine into one set.

- **Format** — blank lines, `#` and `;` comments and any trailing field after whitespace or a comma are skipped, so a CSV export loads unconverted. A line that is not an address is skipped rather than failing the file.
- **A prefix is not an address** — a `198.51.100.0/24` line is skipped like any other, so a CIDR list loads only its bare addresses. `xflow_threat_skipped_lines` counts what the load passed over, blank lines and comments excluded.
- **A line over 255 bytes fails the file** — nothing a list publishes is that long, so such a line says the file is not a list, and a set silently missing its tail would under-flag.
- **An unlisted address is not a clean one** — it is an address no list covers, which is absence rather than a finding.
- **Both directions** — a hit on the source lands on `direction="src"` and one on the destination on `direction="dst"`, which reads as an inside host that reached a flagged destination.
- **Size** — the lists the bundled script fetches combine to roughly 420,000 addresses, about 20 MiB, answering a lookup in tens of nanoseconds.
- **Licence** — several published aggregates inherit a non-commercial clause from an upstream feed; the ones the script fetches are MIT and CC0.

`scripts/fetch-enrichment-data.sh` downloads, merges and deduplicates the published lists, and `fetch-enrichment-data.sh databases` fetches the ASN and country databases from DB-IP unless `MAXMIND_LICENSE_KEY` is set. Both write where `THREAT_FILE`, `ASN_DATABASE` and `COUNTRY_DATABASE` point. The script checks that each body names an address rather than trusting the status, refuses a merge below `MIN_ADDRESSES` (1000) and a multi-part list no part of which reached `SPLIT_PART_LINES` (131072), and exits non-zero naming its reason, so a bad fetch leaves the previous file in place. Run it from cron and reload afterwards.

### Reloading

`--web.enable-lifecycle` exposes `/-/reload`, and a `SIGHUP` does the same without the flag. Both re-read every enrichment source from disk.

- **POST or PUT only**, and unexposed by default, the endpoint being a write — [SECURITY.md](../SECURITY.md) covers the posture.
- **A failed reload keeps the previous data** — a list gone missing would otherwise unflag every address at once, which reads as a network that had just gone clean. `xflow_threat_reload_failures_total` counts those.
- **Atomic** — a new set is built whole before it replaces the old one and each mmdb reader is replaced rather than reopened, so a lookup never sees a half-loaded set and the decode path never pauses.

### Bounded state

Every map keyed by wire data carries a bound, a push protocol not choosing its senders.

| Bounded                            | Limit  | Past it                                                      |
| :--------------------------------- | :----- | :----------------------------------------------------------- |
| Observation domains per device     | 256    | The datagram is discarded, counting `domain_limit`           |
| Templates per domain               | 8192   | Expired templates go first, then `invalid_template`          |
| Interned vendor strings            | 65536  | The value is copied per occurrence rather than refused       |
| One vendor string                  | 255 B  | Refused, as invalid UTF-8 is, counting once per field        |
| Announced applications per device  | 16384  | The application stays numbered rather than named             |
| Devices holding decode statistics  | 65536  | The device decodes but reaches no per-device health series   |
| AS names held from the database    | 65536  | The AS goes unnamed, which a join shows by finding nothing   |

- **Announced applications** — the bound sits an order of magnitude above the 1500 or so an NBAR2 protocol pack names, that database being what the table carries.
- **Refusal counters** — `xflow_domains_refused_total`, `xflow_vendor_strings_refused_total`, `xflow_applications_refused_total` and `xflow_exporters_refused_total` count attempts, and [Health](health.md) carries what each costs the records behind it.
- **Fallback** — a refused vendor string leaves the record on its numbered `applicationId`, on its port name under `--enrich.services`, or on no application series at all, never on a partial name.
- **Sweeps** — idle domains are swept on the template TTL, and idle devices only once the device budget is reached, so a device that has gone silent keeps the freshness series an alert on silence has to read.
- **Not wire-keyed** — the per-device application tables and the distribution histograms key on the source address alone, and are bounded by restricting the receiver to permitted senders ([SECURITY.md](../SECURITY.md)).

### Templates

NetFlow v9 and IPFIX data decode against templates cached per exporter address, protocol and Observation Domain ID together — [Protocols](protocols.md#netflow-v9-and-ipfix) carries the scope rationale, the refusal conditions and the expiry rule.

### Packet sections

A NetFlow-Lite record carries one sampled packet section instead of parsed flow fields, and decodes through the header walk the sFlow decoder uses — [Protocols](protocols.md#netflow-lite) carries the elements, the precedence and the padding ambiguity.

### Remote write

`--remote-write.url` ships the registry's counters and gauges to a Remote Write 2.0 endpoint, alongside or instead of `/metrics`.

- **Cardinality is the caller's to bound** — `--aggregation.top-k` bounds what is live at any instant, not what a long-term store accumulates. The address-keyed families turn their Top-K over as talkers come and go, measured at 5.3× the live series count per hour for `xflow_service_*` on a quiet link and before the ordering fix that removed the share a byte tie was causing, while `asns`, `applications`, `tcp_flags`, `dscp` and `countries` stay flat at 1.0×.
- **Aggregate before shipping** — reduce the address-keyed families with recording rules or drop them with `write_relabel_configs`. Neither the writer nor a scrape filters anything of its own accord.

### Native histograms

`--collector.distributions` publishes `xflow_flow_bytes` and `xflow_flow_duration_seconds` as native histograms, one series per exporter with exponential buckets.

- **Scraping** — Prometheus v3.8+ with `scrape_native_histograms: true`, which [examples/prometheus.yml](../examples/prometheus.yml) sets. Without it the scrape negotiates the classic text exposition, which carries a `_count`, a `_sum` and one `+Inf` bucket.
- **Duration** — observed only where the record carried both flow instants, so sFlow samples and clock-less templates contribute size but no duration.
- **Scrape-only** — Remote Write 2.0 sends a histogram as its own message, and reducing one to a single sample would be a value nobody measured, so `--remote-write.url` ships the counters and gauges alone.

### Dashboards

[examples/grafana_dashboard.json](../examples/grafana_dashboard.json) covers reception and decoding, throughput per device, the Top-K composition views, the aggregation tables and the enrichment sources, with the data source and the devices as variables.

- **Panels rank by packets, not bytes** — both are sampled estimates and a byte figure adds the variance of the packet-size distribution on top, so read volume as a proportion and take an exact figure from the device's SNMP interface counters.
- **The composition panels rank; they do not total** — entries below `--aggregation.top-k` publish nothing, and `other` carries only what the entry bound folded at ingest.
