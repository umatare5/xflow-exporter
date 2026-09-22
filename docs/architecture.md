# Architecture

This document preserves the foundational design and architectural principles of the xflow-exporter.

## Scrape Path

Every scrape is served from the aggregation tables where they stand. No scrape waits on a datagram.

```mermaid
flowchart LR
    L["UDP listeners"] --> Q[["Bounded queue"]]
    Q --> D{"Dispatcher"}
    D -- "hashed by device" --> W["Decode workers"]
    W -- "read lock, write on a new key" --> T[("Aggregation tables")]
    SW["Idle sweeper"] -. "evict on the TTL" ..-> T
    COL["Collector"] -- "read lock, then the cut" ---> T
```

Ingest adds to a present entry's counters as [atomics](../internal/aggregator/table.go#L117) under the table's read lock, which is the lock a scrape takes as well. Only [creating an entry](../internal/aggregator/table.go#L139) or evicting one takes the write lock, so those are the two moments a reader waits for.

Each listener reads a whole batch per `recvmmsg` round trip on Linux and one datagram per call elsewhere. It then offers the datagram to the queue `--receiver.queue-size` bounds with a [non-blocking send](../internal/receiver/receiver.go#L207), and a datagram meeting a full queue is dropped and counted as `queue_full` against its listener.

One dispatcher drains that queue and hands each datagram to the shard of the worker its source address [hashes to](../internal/server/lifecycle.go#L404), which keeps one device's records in arrival order. That hand-off blocks on a shard [64 datagrams deep](../internal/server/lifecycle.go#L375), so a worker falling behind stops the dispatcher and the shared queue then drops for every device on the listener rather than for the slow one alone.

## Endpoints

The exporter serves `/metrics`, `/entries`, `/healthz`, `/-/reload` and a landing page at `/`. None of them authenticates – [`SECURITY.md`](../SECURITY.md) specifies the network path they belong on.

| Path        | Methods   | Status             | Behavior                                   |
| :---------- | :-------- | :----------------- | :----------------------------------------- |
| `/metrics`  | Any       | 200, 503           | 503 past ten concurrent gathers            |
| `/entries`  | GET       | 200, 400, 405, 503 | 400 names the values, 503 past one listing |
| `/healthz`  | Any       | 200                | Static `OK`, reading no state              |
| `/-/reload` | POST, PUT | 200, 405, 500      | 405 sets `Allow`, 500 names the error      |
| `/`         | Any       | 200                | Catch-all landing page, never 404          |

The `/` route matches every unclaimed path, so an unknown one returns the landing page. A flag left unset leaves its route unregistered, so a disabled `/entries` and a misspelled path answer alike.

The `/healthz` endpoint returns a static 200 without reading the registry or the tables. That makes it a liveness probe and never a readiness one, because a push protocol offers no arrival an endpoint could wait for.

The `/metrics` handler admits [ten concurrent gathers](../internal/server/server.go#L56) and answers the eleventh with 503. Every route carries a [60-second write deadline](../internal/server/server.go#L21) and a 30-second header timeout. The `/entries` body is the largest the process writes, so that route [restarts the deadline](../internal/server/entries.go#L73) at its own body and frees its slot rather than waiting on a disconnect.

## Absence

A device omits a field its template never declared. Absence on the wire is not a reading, and publishing `0` for it invents one.

A dimension no record carried opens no entry and publishes no series, never `0`, `false`, `NaN` or an epoch instant. An aggregated cache feeds `xflow_exporter_*` alone for the same reason, because every other family would re-count traffic the device's main cache already reported.

The counts follow that rule per family. An entry [latches](../internal/aggregator/table.go#L42) on the first record that kept its byte or packet total in unread elements and [withholds that family](../internal/collector/flows.go#L89) from then on, a partial sum reading exactly like a complete one. The latch never clears, because an entry whose sum lost a contribution stays short however many complete records follow.

Eviction is the push model's spelling of absence. A conversation nobody has seen for `--aggregation.entry-ttl` is not a zero, it is gone, and its series goes with it. Instants and rates are read at decode rather than at scrape, so a series carries what the device reported and not what Prometheus asked for.

## Decoder

A template cache holds every NetFlow v9 and IPFIX layout, keyed on [the exporter address, the protocol and the observation domain](../internal/decoder/templates.go#L91). The address and the domain scope a template the way RFC 7011 does, and the protocol joins them because three decoders share this store, each numbering its templates from 256 in a space of its own.

A v9 Source ID, an IPFIX Observation Domain ID and an sFlow sub-agent id are unrelated numbers that collide freely. A device exporting two protocols from one address would otherwise decode a data set against whichever protocol announced the id last. That miss is silent, because the record walks to a length the fields agree on and reaches the aggregator as a measurement.

sFlow ships sampled packet headers rather than flow state, so each readable record decodes into one single-packet record the sample's own rate then scales. A packet section is [kept until every field is read](../internal/decoder/fields.go#L89), so a device's own parsed fields win over the header the exporter would otherwise walk.

## Sampling Correction

The product is formed at decode and stored, so every table holds corrected volumes and no consumer re-applies a rate. A record carrying no rate multiplies by one, and both products [saturate rather than wrap](../internal/flow/flow.go#L224), because a counter handed a reading below the one before it reads as a reset.

The rate comes from a v5 header, an options declaration or an sFlow sample's own field. An sFlow rate rides its sample and reaches no health series, while a v9 or IPFIX declaration is tracked per domain and published.

[Correction precedence](health.md#technical-notes) carries the order a record resolves in, and `xflow_sampling_unresolved_flows_total` counts the records reaching its end with nothing to apply.

## Counter Semantics

An entry's counters start at its creation and end at its eviction, and its series ends with it. Prometheus marks a series absent from the next scrape stale, so the entry's next incarnation reads as a new series rather than as a counter that fell. Flow counts are the figures the records reported and take no sampling correction.

The `other` series carries the keys `--aggregation.max-entries` refused at ingest, and nothing else. An evicted entry is not folded into it: its bytes already reached Prometheus as increments on its own series. Publishing that lifetime a second time would make `sum(rate())` over the family read double.

The tail below the [Top-K and min-bytes cuts](../internal/collector/flows.go#L531) is withheld rather than folded, for the same reason. Its entries are still accumulating, so summing them per scrape would make a counter that falls whenever one is evicted or grows into the cut. Entries the byte counts cannot separate are ordered by age, because at one in N a tie group straddling the cut would otherwise churn the series set on every scrape.

## Bounded State

Every map keyed by wire data takes a bound, because a push protocol cannot choose its senders.

| Bounded                           | Limit                                        | Action at the limit                              |
| :-------------------------------- | :------------------------------------------- | :----------------------------------------------- |
| Observation domains per device    | [256](../internal/decoder/templates.go#L37)  | Discard the record; v5 and v8 lose sequence      |
| Devices holding domain state      | [65536](../internal/decoder/stats.go#L29)    | Discard the datagram; v5 and v8 lose sequence    |
| Templates per domain              | [8192](../internal/decoder/templates.go#L18) | Prune expired, then reject as `invalid_template` |
| Samplers per domain               | [4096](../internal/decoder/templates.go#L23) | Prune idle, then leave the sampler untracked     |
| Transport sessions per domain     | [16](../internal/decoder/templates.go#L44)   | Leave that session's sequence unfollowed         |
| Sampler declarations per device   | [256](../internal/decoder/templates.go#L49)  | Refuse; records take the device's own rate       |
| Interned vendor strings           | [65536](../internal/decoder/apps.go#L173)    | Copy per occurrence rather than refuse           |
| One vendor string                 | [255 B](../internal/decoder/apps.go#L180)    | Refuse like invalid UTF-8, once per field        |
| Announced applications per device | [16384](../internal/decoder/apps.go#L38)     | Leave the application numbered, never named      |
| Devices with decode statistics    | [65536](../internal/decoder/stats.go#L29)    | Decode on, but publish no decode counters        |
| AS names cached from the database | [65536](../internal/enrich/mmdb.go#L86)      | Leave the AS unnamed; a join finds no name       |

A device reporting both observation points of one path keys each conversation twice, so the aggregation entry bound covers roughly half as many of them. A device reporting one point, or none, is unaffected.

The six `_refused_total` counters rise per attempt rather than per entity, so one flooding sender moves them faster than the state it failed to open. The application bounds hold ten times a standard NBAR2 pack, aggregation tables are bounded by `--aggregation.max-entries`, and the two histograms by their bucket cap and the device budget.

Idle domains, sampler declarations and application tables expire on `--parser.template-ttl` in a sweep, while a device is reclaimed only once the fleet budget is reached. A refused device keeps decoding and feeding the aggregation tables, losing its decode counters and timestamps alone. The two domain budgets bound a product: a full fleet holds 256 domains per device.
