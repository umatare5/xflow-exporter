# Documentation

Reference pages for xflow-exporter. The [README](../README.md) covers getting flows received and scraped, and these pages carry the full metric catalogue and the behaviour every module shares.

| Page                              | Focus                                     |
| :-------------------------------- | :---------------------------------------- |
| [Collectors](collectors.md)       | Every metric family and its labels        |
| [Configuration](configuration.md) | Flags and defaults, as `--help` prints    |

## Technical Information

### Absence

A dimension a flow record did not carry produces no series: never `0`, `false` or an epoch timestamp. Prometheus cannot distinguish a fabricated zero from a measured one.

- **Ingest** — a record without addresses feeds no host or service entry, one without an application feeds no application entry, and a NetFlow v8 aggregate feeds only the tables its method's dimensions cover.
- **Eviction** — an aggregation entry idle past `--aggregation.entry-ttl` is removed and its series disappears. A flow nobody has seen is gone, not zero.
- **Freshness** — `xflow_last_flow_timestamp_seconds` exists only once a device's datagram has decoded, and `xflow_sampling_rate` only once a rate has arrived.

### Counter semantics

The table families are counters accumulated since each entry was created, and an entry evicted then re-created restarts from zero.

- **Ranges** — give `rate()` a range that spans several scrapes; the staleness marker Prometheus writes at eviction separates the old series from a rebirth.
- **Folding** — the `other` series of each family is seeded at zero and absorbs the Top-K tail, the byte-threshold tail, and what the entry bound rejected, so a first fold is a rise on an existing series.
- **Flow counts** — `_flows_total` is as exported: a packet-sampling protocol observes flows rather than counting them, so no sampling multiplication is applied to it.

### Sampling correction

`_bytes_total` and `_packets_total` are multiplied by the sampling rate in force when the record was decoded.

- **Sources** — the v5 header interval, the v9/IPFIX options (PSAMP interval and space pair first, then the random-sampler interval, then the plain interval), and the per-sample rate sFlow carries inline.
- **Audit** — `xflow_sampling_rate` publishes the rate each observation domain declared, so a corrected series can be traced to the rate that scaled it.
- **Unsampled** — a record carrying no rate multiplies by one; PAN-OS NetFlow is always unsampled.

### Templates

NetFlow v9 and IPFIX data decode against templates cached per exporter address and Observation Domain ID together, per RFC 7011.

- **Startup** — `missing_template` rejections are expected after a restart until each device re-announces; a device that never does keeps the counter rising, which is the signal to check its template refresh configuration.
- **Limits** — a template with a zero-width fixed field, more than `--parser.max-fields-per-template` fields, or specifiers that overrun their set is refused as `invalid_template`.
- **Expiry** — a template unrefreshed for `--parser.template-ttl` stops serving: an orphaned template may describe a schema the device has replaced.

### Native histograms

`--collector.distributions` publishes `xflow_flow_bytes` and `xflow_flow_duration_seconds` as native histograms, one series per exporter with exponential buckets.

- **Scraping** — Prometheus v3.8+ with native histogram ingestion enabled in the scrape configuration; the classic text exposition carries only `_count` and `_sum`.
- **Duration** — observed only where the record carried both flow instants; sFlow samples and clock-less templates contribute size but no duration.
