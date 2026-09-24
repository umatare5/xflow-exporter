# Security Policy

Please follow **[the shared security policy](https://github.com/umatare5/.github/blob/main/SECURITY.md)**, which covers:

- **Supported Versions** – only the latest release carries fixes, so reproduce against it.
- **Reporting a Vulnerability** – the private advisory path and what the response promises.
- **What to Include** – the credentials and addresses to redact, and the fields to send.
- **Exposure** – the unauthenticated surface and the container the image ships.
- **Out of Scope** – findings that belong to the monitored system or to an operator's own configuration.

This page specifies what is particular to this one.

## What to Include

Reproduction needs the flags in force and the datagram that triggers the defect. Prefer a synthetic datagram over a capture of a production link, because the capture discloses the traffic the list below redacts.

Redact these before reporting, in addition to the credentials the shared policy names.

- **Infrastructure** – A monitored address, from a datagram, a capture, `/metrics` or `/entries`.
- **Application** – The exporting device's address, and any name a mapping file supplied.
- **Credentials** – A remote write credential, from a flag, an environment variable or a header.

## Exposure

This exporter receives NetFlow, IPFIX and sFlow records from network devices over UDP, and exposes them as Prometheus metrics.

- **Datagrams** – each incoming packet is treated as untrusted input and processed accordingly.
- **Transport** – UDP alone, without the SCTP and DTLS RFC 7011 requires of an IPFIX collector, so every datagram arrives unauthenticated and in the clear.
- **Records** – the aggregates disclose who talked to whom, with addresses, ports and volumes.
- **Labels** – collectors are off by default, and enabling one publishes monitored addresses.
- **Names** – `--enrich.mapping-file` adds internal device and interface names to those series.

## Endpoints

No route authenticates, so the network path the listener sits on is the whole access control. See also [Endpoints](docs/architecture.md#endpoints).

- **Listener** – `--web.listen-address` defaults to `0.0.0.0`, which answers on every interface.
- **Lifecycle** – `--web.enable-lifecycle` exposes `/-/reload` to any client reaching the listener.
- **Effect** – a reload re-reads the enrichment files from disk and changes no other state.
- **Signal** – `SIGHUP` performs that same reload, so local control needs neither flag nor route.
- **Entries** – `--web.enable-aggregation-entries` exposes `/entries`, which reads whole tables.
- **Disclosure** – that listing carries the pairs the Top-K cut keeps off `/metrics`.
- **Restriction** – with either flag set, put a packet filter or an authenticating proxy in front.

## Ingress Paths

A datagram's source address is the sender's identity and the key both template scoping and per-device state use. Nothing verifies it, so restricting who reaches the receiver port is the only control over either.

- **Reach** – `--receiver.address` defaults to `:4739`, which accepts every host that routes to it.
- **No allowlist** – the exporter filters no sender, which leaves the packet filter to enforce it.
- **Spoofing** – a forged source address and port write into the template cache the real device keys.
- **Corruption** – that device's later records decode against the template an attacker announced.
- **Address alone** – a forged address still acts on that device's series, budgets and declarations.
- **Budgets** – every table a sender fills is bounded, and [Bounded state](docs/architecture.md#bounded-state) lists each bound.
- **A UDP proxy translates the source** – every device then arrives at the receiver as one address.
- **Device state merges** – declarations cross devices, and one proxy port lets templates collide.

```bash
nft add rule inet filter input udp dport 4739 ip saddr { 10.0.0.0/24, 192.0.2.10 } accept
nft add rule inet filter input udp dport 4739 drop
```

> [!IMPORTANT]
> The receive path bounds datagram size at `--receiver.max-packet-size`, and the parsers bound field counts, the template fields and observation domains per device, and interned vendor strings. Input that evades any of those bounds is a vulnerability – memory exhaustion, a panic and a read past a bound alike – because they are what keeps an untrusted sender from taking the process down.

## Egress Paths

The exporter opens one outbound connection, and only where `--remote-write.url` is set. Every other data path reads a file on local disk, and no code path reports telemetry or checks for updates.

### Enrichment

- **Local only** – every source reads a file on disk, and a lookup sends no address anywhere.
- **Fetching** – [`scripts/fetch-enrichment-data.sh`](scripts/fetch-enrichment-data.sh) downloads the data.
- **SNMP** – the exporter speaks none, and [`scripts/fetch-device-names.sh`](scripts/fetch-device-names.sh) walks the devices.
- **Community string** – `SNMP_OPTIONS` is exposed via command-line arguments, which `ps` shows.
- **Mitigation** – leave `SNMP_OPTIONS` empty and set `defCommunity` in `snmp.conf` instead.

### Remote Write

- **Payload** – counters and gauges, including the monitored addresses a scrape exposes.
- **Cleartext** – validation accepts an `http://` URL, over which basic auth travels in the clear.
- **Requirement** – use `https://`, because nothing in the client refuses the cleartext path.
- **Verification** – writes travel on Go's default transport, so certificate verification is on.
- **Proxy** – that transport reads `HTTPS_PROXY`, which redirects the writes and the credential.
- **Process table** – a credential given as a flag is readable in `ps` by every account on the host.
- **Environment** – the credential variables keep it off argv, and [Help](docs/help.md) names them.
- **Headers** – `--remote-write.header` attaches any header, a bearer token included.

## Out of Scope

- **Origin** – A defect in a network device's own flow export belongs to that vendor rather than to this exporter.
- **Reading** – A value that follows a non-conforming export, because a decoder publishes what the wire carried.
