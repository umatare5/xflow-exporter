# Security Policy

The [shared security policy](https://github.com/umatare5/.github/blob/main/SECURITY.md) covers what every exporter here shares. This page carries the rest.

## What to Include

Redact these before reporting, in addition to the credentials the shared policy names.

- A monitored address, from a datagram, a capture or a `/metrics` sample
- The exporting device's address, and any name a mapping file gave it
- A remote write credential, from a flag, an environment variable or a header

Reproduction needs the flags in force and the datagram or capture that triggers it.

## Exposure

This exporter receives NetFlow, IPFIX and sFlow records from network devices over UDP, and exposes aggregates of them as Prometheus metrics. Every received datagram is untrusted, and the parsers bound it.

- **Flow records** — they reveal who talked to whom, with addresses, ports and volumes.
- **Labels** — collectors are off by default, and enabling one publishes monitored addresses.
- **Senders** — restrict the receiver port to your own devices at the packet filter.

```bash
nft add rule inet filter input udp dport 4739 ip saddr { 10.0.0.0/24, 192.0.2.10 } accept
nft add rule inet filter input udp dport 4739 drop
```

> [!IMPORTANT]
> The receiver bounds a datagram at `--receiver.max-packet-size`, and the parsers bound field counts, observation domains per device and interned vendor strings, so a way around any of them is a vulnerability.
>
> State keyed by the source address grows with every distinct sender, and a push protocol cannot choose them, so the restriction belongs at the filter. A proxy is no substitute: it replaces the source address, which collapses every device into one and breaks the template scoping RFC 7011 requires.

## Egress Paths

Nothing leaves the host unless `--remote-write.url` is set.

### Remote Write

- **Payload** — counters and gauges, carrying the monitored addresses a scrape exposes.
- **Interval** — the client gathers the registry every `--remote-write.interval`, 60s by default.
- **Credentials** — `--remote-write.username` and `--remote-write.password` send basic auth.
- **Environment** — `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD` do the same.
- **Headers** — `--remote-write.header` attaches any header, including a bearer token.
- **Plain HTTP** — validation accepts an `http://` URL without a warning.
- **Cleartext** — basic auth over it travels in the clear, so use `https://` off a trusted path.

### Enrichment

- **Local only** — every source reads a file on disk, and a lookup sends no address anywhere.
- **Fetching** — the operator runs [`scripts/fetch-enrichment-data.sh`](scripts/fetch-enrichment-data.sh).
- **SNMP** — this exporter speaks none, and [`scripts/fetch-device-names.sh`](scripts/fetch-device-names.sh) walks the devices.
- **Community string** — `SNMP_OPTIONS` rides the `snmpwalk` command line, where `ps` shows it.
- **Hiding it** — set `SNMP_OPTIONS` empty and put `defCommunity` in `snmp.conf` instead.

### Reload

- **Endpoint** — `--web.enable-lifecycle` exposes an unauthenticated `/-/reload`.
- **Effect** — it re-reads the enrichment sources, so keep it on a controlled path.
- **Signal** — a `SIGHUP` reloads the same sources without exposing anything.

## Out of Scope

A defect in a network device's own flow export implementation belongs to its vendor.
