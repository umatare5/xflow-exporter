# Security Policy

## Supported Versions

Only the latest release carries fixes, and no older tag gets a patch branch. Reproduce a finding against that release before reporting it.

## Reporting a Vulnerability

Report privately through [GitHub Security Advisories](https://github.com/umatare5/xflow-exporter/security/advisories/new), never through an issue or a pull request. One maintainer works on this in their own time, so no response time is promised. The advisory goes out after the fix ships and credits the reporter unless they ask otherwise.

## What to Include

**Redact these first.** None of them belongs in a report.

- A monitored address, from a datagram, a capture or a `/metrics` sample
- The exporting device's address, and any name a mapping file gave it
- A remote write credential, from a flag, an environment variable or a header

Then include the following.

- **Affected versions** — name the `xflow-exporter` release, plus the device and its firmware.
- **Reproduction steps** — list the flags in force, the datagram or capture that triggers it, and the log line, metric or stack trace it produced.
- **Impact** — state what the exploit reaches, given an unauthenticated receiver and `/metrics`.
- **Disclosure status** — say whether it is shared elsewhere, and give your plan for sharing it.
- **Suggested fix** — propose a remediation where you have one; this one is optional.

## Exposure

This exporter receives NetFlow, IPFIX and sFlow records from network devices over UDP, and exposes aggregates of them as Prometheus metrics. Every received datagram is untrusted, and the parsers bound it.

Flow records reveal who talked to whom, and carry the addresses, ports and volumes of the monitored networks, so the receiver and `/metrics` both need a controlled network path.

- **Metrics** — `/metrics` serves unauthenticated plain HTTP whose labels carry monitored addresses.
- **Container** — the image is built from `scratch`, runs as UID 65534 and carries one CA bundle, which the remote-write client alone uses because nothing else calls out over TLS.

Restrict the receiver port to your own devices at the packet filter, as nftables does here.

```bash
nft add rule inet filter input udp dport 4739 ip saddr { 10.0.0.0/24, 192.0.2.10 } accept
nft add rule inet filter input udp dport 4739 drop
```

> [!IMPORTANT]
> The parsers enforce hard limits on field counts, datagram sizes, observation domains per device and interned vendor strings, so a way around any of them is a vulnerability.
>
> State keyed by the source address grows with every distinct sender, and a push protocol cannot choose them, so the restriction belongs at the filter. A proxy is no substitute: it replaces the source address, which collapses every device into one and breaks the template scoping RFC 7011 requires.

## Egress

Nothing leaves the host unless `--remote-write.url` is set, and a write carries the monitored addresses a scrape exposes, so point it only at a store trusted with flow data.

- **Remote write** — `--remote-write.url` enables the Remote Write 2.0 client, which gathers the registry every `--remote-write.interval`, 60 seconds by default, and sends its counters and gauges.
- **Credentials** — `--remote-write.username` and `--remote-write.password`, or `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD`, send basic auth.
- **Headers** — `--remote-write.header` attaches any header, including a bearer token.
- **Plain HTTP** — validation accepts an `http://` URL without a warning, and basic auth over it travels in cleartext, so use `https://` on any path that is not fully trusted.
- **Enrichment** — every source reads a local file, and a lookup sends no address anywhere; the operator fetches threat lists and MaxMind-format databases through [`scripts/fetch-enrichment-data.sh`](scripts/fetch-enrichment-data.sh).
- **SNMP** — this exporter speaks none, and [`scripts/fetch-device-names.sh`](scripts/fetch-device-names.sh) walks the devices with `SNMP_OPTIONS` on the `snmpwalk` command line, where every account on the host reads it out of `ps`.
- **Community string** — set `SNMP_OPTIONS` empty and put `defCommunity` in `snmp.conf` instead, wherever the community string is not already public.
- **Reload** — `--web.enable-lifecycle` exposes an unauthenticated `/-/reload`, which re-reads the enrichment sources on request, so keep it on a controlled path or leave the flag off and reload with a `SIGHUP`.

## Out of Scope

A defect in a network device's own flow export implementation belongs to that device's vendor — report it there, not to this third-party exporter. A dependency advisory with no path reachable from `./cmd` is out of scope as well — show the reachable path, or the `govulncheck` finding that proves it.
