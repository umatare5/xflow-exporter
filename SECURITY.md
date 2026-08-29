# Security Policy

## Supported versions

Only the latest release carries fixes, and no older tag gets a patch branch. Reproduce a finding against the latest release before reporting it.

## Reporting a vulnerability

Report privately through GitHub Security Advisories, never an issue or a pull request — open the repository's **Security** tab and choose **Report a vulnerability**.

One maintainer works on this in their own time, so no response time is promised. The advisory goes out after the fix ships and credits the reporter unless they ask otherwise.

## What this exporter holds and exposes

This exporter receives traffic flow records (NetFlow, IPFIX, sFlow) from network devices over UDP, and exposes aggregates of them as Prometheus metrics. Flow records reveal who talked to whom, so both the receiver and the metrics endpoint deserve a controlled network path.

- **Flow records** — IP addresses, ports and traffic volumes of monitored networks, so keep the receiver reachable from the exporting devices alone.
- **Parser input** — every received datagram is untrusted input, and the parsers enforce hard limits on field counts, record sizes, observation domains per device and interned vendor strings. Report a way around those limits as a vulnerability.
- **Permitted senders** — restrict the receiver port to your own devices at the packet filter. State keyed by the source address grows with the number of distinct senders, and a push protocol cannot choose them. A proxy is not a substitute: it replaces the source address, which collapses every device into one and breaks the template scoping RFC 7011 requires.
- **Metrics** — unauthenticated plain HTTP whose label sets can carry monitored IP addresses, so keep it on a controlled path.

Restricting the port looks like this with nftables.

```bash
nft add rule inet filter input udp dport 2055 ip saddr { 10.0.0.0/24, 192.0.2.10 } accept
nft add rule inet filter input udp dport 2055 drop
```

## What leaves the host

Nothing, unless `--enrich.threat-api-key` is set. That flag sends the public
addresses seen in flows to AbuseIPDB to be scored. Addresses the monitored
network assigns itself are never sent, and every other enrichment source
reads a file on local disk.

## Out of scope

A defect in a network device's own flow export implementation belongs to its vendor — report it there, not to this third-party exporter.
