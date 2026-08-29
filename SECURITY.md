# Security Policy

## Supported versions

Only the latest release carries fixes, and no older tag gets a patch branch. Reproduce a finding against the latest release before reporting it.

## Reporting a vulnerability

Report privately through GitHub Security Advisories, never an issue or a pull request — open the repository's **Security** tab and choose **Report a vulnerability**.

One maintainer works on this in their own time, so no response time is promised. The advisory goes out after the fix ships and credits the reporter unless they ask otherwise.

## What this exporter holds and exposes

This exporter receives traffic flow records (NetFlow, IPFIX, sFlow) from network devices over UDP, and exposes aggregates of them as Prometheus metrics. Flow records reveal who talked to whom, so both the receiver and the metrics endpoint deserve a controlled network path.

- **Flow records** — IP addresses, ports and traffic volumes of monitored networks; keep the receiver reachable from the exporting devices alone.
- **Parser input** — every received datagram is untrusted input, and the parsers enforce hard limits on field counts and record sizes; report a way around those limits as a vulnerability.
- **Metrics** — unauthenticated plain HTTP whose label sets can carry monitored IP addresses, so keep it on a controlled path.

## Out of scope

A defect in a network device's own flow export implementation belongs to its vendor — report it there, not to this third-party exporter.
