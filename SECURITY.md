# Security Policy

The [shared policy](https://github.com/umatare5/.github/blob/main/SECURITY.md) carries the supported versions, the reporting channel, what a report must contain and the out-of-scope list. This page carries what is specific to a flow collector.

## What to Include

Redact these before reporting, in addition to the credentials the shared policy names.

- A monitored address, from a datagram, a capture or a `/metrics` sample
- The exporting device's address, and any name a mapping file gave it
- A remote write credential, from a flag, an environment variable or a header

Reproduction needs the flags in force and the datagram or capture that triggers it.

## Exposure

This exporter receives NetFlow, IPFIX and sFlow records from network devices over UDP, and exposes aggregates of them as Prometheus metrics. Every received datagram is untrusted, and the parsers bound it.

Flow records reveal who talked to whom, and carry the addresses, ports and volumes of the monitored networks, so the receiver and `/metrics` both need a controlled network path.

- **Metrics** — every collector is off by default, and enabling one puts monitored addresses in the labels of an unauthenticated plain-HTTP endpoint.
- **Senders** — restrict the receiver port to your own devices at the packet filter.

```bash
nft add rule inet filter input udp dport 4739 ip saddr { 10.0.0.0/24, 192.0.2.10 } accept
nft add rule inet filter input udp dport 4739 drop
```

> [!IMPORTANT]
> The receiver bounds a datagram at `--receiver.max-packet-size`, and the parsers bound field counts, observation domains per device and interned vendor strings, so a way around any of them is a vulnerability.
>
> State keyed by the source address grows with every distinct sender, and a push protocol cannot choose them, so the restriction belongs at the filter. A proxy is no substitute: it replaces the source address, which collapses every device into one and breaks the template scoping RFC 7011 requires.

## Egress

Nothing leaves the host unless `--remote-write.url` is set, and a write carries the monitored addresses a scrape exposes, so point it only at a store trusted with flow data.

- **Remote write** — the Remote Write 2.0 client gathers the registry every `--remote-write.interval`, 60 seconds by default, and sends its counters and gauges.
- **Credentials** — `--remote-write.username` and `--remote-write.password`, or `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD`, send basic auth.
- **Headers** — `--remote-write.header` attaches any header, including a bearer token.
- **Plain HTTP** — validation accepts an `http://` URL without a warning, and basic auth over it travels in cleartext, so use `https://` on any path that is not fully trusted.
- **Enrichment** — every source reads a local file and a lookup sends no address anywhere; the operator fetches the lists and databases through [`scripts/fetch-enrichment-data.sh`](scripts/fetch-enrichment-data.sh).
- **SNMP** — this exporter speaks none, and [`scripts/fetch-device-names.sh`](scripts/fetch-device-names.sh) walks the devices with `SNMP_OPTIONS` on the `snmpwalk` command line, where every account on the host reads it out of `ps`.
- **Community string** — set `SNMP_OPTIONS` empty and put `defCommunity` in `snmp.conf` instead.
- **Reload** — `--web.enable-lifecycle` exposes an unauthenticated `/-/reload`, which re-reads the enrichment sources on request, so keep it on a controlled path or reload with a `SIGHUP`.

## Out of Scope

A defect in a network device's own flow export implementation belongs to its vendor.
