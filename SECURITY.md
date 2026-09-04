# Security Policy

## Supported versions

Only the latest release carries fixes, and no older tag gets a patch branch. Reproduce a finding against the latest release before reporting it.

## Reporting a vulnerability

Report privately through GitHub Security Advisories, never an issue or a pull request — open the repository's **Security** tab and choose **Report a vulnerability**.

One maintainer works on this in their own time, so no response time is promised. The advisory goes out after the fix ships and credits the reporter unless they ask otherwise.

## What this exporter holds and exposes

This exporter receives traffic flow records (NetFlow, IPFIX, sFlow) from network devices over UDP, and exposes aggregates of them as Prometheus metrics. Flow records reveal who talked to whom, so both the receiver and the metrics endpoint deserve a controlled network path.

- **Flow records** — IP addresses, ports and volumes of the monitored networks.
- **Parser input** — every received datagram is untrusted, and the parsers bound it.
- **Permitted senders** — restrict the receiver port to your own devices at the filter.
- **Metrics** — unauthenticated plain HTTP whose labels can carry monitored addresses.

> [!IMPORTANT]
> Keep the receiver reachable from the exporting devices alone, and the metrics endpoint on a controlled path. The parsers enforce hard limits on field counts, record sizes, observation domains per device and interned vendor strings — report a way around any of them as a vulnerability. State keyed by the source address grows with the number of distinct senders, and a push protocol cannot choose them, so a proxy is no substitute: it replaces the source address, which collapses every device into one and breaks the template scoping RFC 7011 requires.

Restricting the port looks like this with nftables.

```bash
nft add rule inet filter input udp dport 2055 ip saddr { 10.0.0.0/24, 192.0.2.10 } accept
nft add rule inet filter input udp dport 2055 drop
```

## What leaves the host

Nothing, unless `--remote-write.url` is set. That flag enables the Remote Write 2.0 client, which gathers the registry every `--remote-write.interval` (default 60 seconds) and sends its counters and gauges to the configured endpoint. Label sets can carry monitored IP addresses, so a write carries what a scrape exposes — point it only at a store trusted with flow data.

When remote write is enabled, the exporter holds that endpoint's credentials: `--remote-write.username` and `--remote-write.password` (or `XFLOW_REMOTE_WRITE_USERNAME` and `XFLOW_REMOTE_WRITE_PASSWORD`) send basic auth, and `--remote-write.header` attaches arbitrary request headers, which can carry a bearer token. Validation accepts a plain `http://` URL without a warning, and basic auth over it travels in cleartext, so use `https://` on any path that is not fully trusted.

Every enrichment source reads a file on local disk, and a lookup sends no address anywhere. Fetching the threat lists and the MaxMind-format databases is a separate job, run by the operator through [`scripts/fetch-enrichment-data.sh`](scripts/fetch-enrichment-data.sh) or any equivalent.

The same holds for the mapping file: this exporter speaks no SNMP, and [`scripts/fetch-device-names.sh`](scripts/fetch-device-names.sh) is what walks the devices. Its `SNMP_OPTIONS` reaches `snmpwalk` on the command line, where every account on the host reads it out of `ps`. Set that variable empty and put `defCommunity` in `snmp.conf` wherever the community string is not already public.

`--web.enable-lifecycle` exposes `/-/reload`, which re-reads those files. It is unauthenticated, like the metrics endpoint, so keep it on a controlled path. It is off by default, and a `SIGHUP` reloads without exposing anything.

## Out of scope

A defect in a network device's own flow export implementation belongs to its vendor — report it there, not to this third-party exporter.
