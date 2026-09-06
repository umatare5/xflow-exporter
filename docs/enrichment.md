# Enrichment

An `--enrich.*` source supplies what the device did not: a dimension of the record itself, or a name for one the record carries as a number. Every source reads a file on local disk, is off by default, and fills absence alone, so an exported reading always wins.

## Sources

| Flag                        | Fills                                    | Feeds                             |
| :-------------------------- | :--------------------------------------- | :-------------------------------- |
| `--enrich.services`         | The application, from the transport port | `applications`                    |
| `--enrich.asn-database`     | The AS numbers, from a MaxMind-format DB | `asns`                            |
| `--enrich.country-database` | The ISO country codes, from the same     | `countries`                       |
| `--enrich.threat-file`      | A flag on addresses a list file names    | `threats`                         |
| `--enrich.mapping-file`     | Device, interface and port names         | The naming series, `applications` |

- **Lookups are local** — nothing is fetched and no credential is held, so a label never costs the exporter a network round trip.
- **A path that cannot be opened fails startup** — and `--dry-run` opens every source the same way, binding nothing — [Help](help.md#notes) carries what else it checks.
- **Nothing ships here** — neither database nor list is bundled, and [`scripts/fetch-enrichment-data.sh`](../scripts/fetch-enrichment-data.sh) is one way to fetch them.
- **A fetch takes effect on reload** — either script writes a file the exporter reads only when told to, so run it from cron and reload afterwards.
- **Coverage is published** — `xflow_enrichment_lookups_total` counts the records each source saw by outcome — [Health](health.md#labels) carries what `filled`, `unknown` and `skipped` mean.

## Service names

`--enrich.services` names the application from the transport port where the device named none, out of a built-in table that [`internal/enrich/services.go`](../internal/enrich/services.go) is the authoritative list of.

- **Protocols, not products** — the table names what a port is registered for, so a product's port belongs in a mapping file rather than here.
- **Destination first** — each table tries the destination port, then the source port, so a device exporting the return direction still names the service side.
- **The mapping file outranks it** — a `services:` entry names any port both cover, and `mapping` runs first, so a source port it names beats a destination port only the built-in table names.
- **Unnamed records open no entry** — a record neither the device nor a table named reaches no `applications` series, so a sum over that family is the named traffic alone.

## Databases

`--enrich.asn-database` and `--enrich.country-database` read MaxMind-format files, which GeoLite2 and DB-IP both publish, and the AS numbers fill only where the device exported none.

- **Fetching** — `fetch-enrichment-data.sh databases` takes both from DB-IP, or from MaxMind when `MAXMIND_LICENSE_KEY` is set, and writes where `ASN_DATABASE` and `COUNTRY_DATABASE` point.
- **Names ride their own series** — `xflow_asn_info` carries the organization the database names, and holds as many as [Bounded state](README.md#bounded-state) tabulates.
- **Replaced whole** — the exporter memory-maps each file, so a fetch installs by rename rather than writing into a file a reader is serving.
- **A country is a registration** — the database places a prefix where it is registered, not where the traffic went — [Collectors](collectors.md#specifications) carries how the pair reads.

## Threat lists

`--enrich.threat-file` reads flagged addresses, one per line, and is repeatable so several lists combine into one set.

- **Format** — one address per line; blank lines, `#` and `;` comments and trailing fields are skipped.
- **A prefix is not an address** — a CIDR line is skipped like any other non-address, and counted in `xflow_threat_skipped_lines`.
- **A line over 255 bytes fails the file** — nothing a list publishes is that long.
- **An unlisted address is not a clean one** — it is absence rather than a finding.
- **Both directions** — a hit on either address keys `direction="src"` or `direction="dst"`.
- **Size** — roughly 420,000 addresses, about 20 MiB, answering a lookup in nanoseconds.
- **License** — the lists the bundled script fetches are MIT and CC0, though others differ.
- **Fetching** — `fetch-enrichment-data.sh threats` downloads, merges and deduplicates the published lists into `THREAT_FILE`. It refuses a merge that fell below its address floor and leaves the previous file in place on failure.

> [!IMPORTANT]
> An over-long line fails the whole file because the reader cannot resume past it, and a set silently missing its tail would under-flag. Several published aggregates inherit a non-commercial clause from an upstream feed.

## Mapping file

`--enrich.mapping-file` names devices and their interfaces, which no flow protocol carries, and may name transport ports the built-in table does not cover. [`examples/mapping.yml`](../examples/mapping.yml) carries the layout.

- **Two info series** — `xflow_device_info` and `xflow_interface_info` carry the names — [Collectors](collectors.md#specifications) carries what both follow.
- **Strict** — an unusable key or name, or one address spelled twice, fails the whole load.
- **Exactly one document** — an empty file and a trailing `---` are both refused.
- **`devices: {}` loads** — emptying the file on purpose is how a reload takes names away.
- **YAML acts first** — the library drops a `~` key before any check and refuses `%YAML 1.2`.
- **Fetching** — [`scripts/fetch-device-names.sh`](../scripts/fetch-device-names.sh) walks the devices over SNMP and writes the file whole, so a hand-written `services:` block lives elsewhere. It refuses a device answering no usable name rather than writing it out unnamed — [`SECURITY.md`](../SECURITY.md) carries where the community string ends up.

This joins a name onto the per-interface traffic of one device, keeping the rows no name reaches:

```promql
sum by (exporter_address, ifname) (
  sum without (src, dst, output_ifindex) (rate(xflow_host_pair_bytes_total[5m]))
  * on (job, instance, exporter_address, input_ifindex) group_left (ifname)
    label_replace(xflow_interface_info, "input_ifindex", "$1", "ifindex", "(.+)")
)
or
sum by (exporter_address, input_ifindex) (
  sum without (src, dst, output_ifindex) (rate(xflow_host_pair_bytes_total[5m]))
  unless on (job, instance, exporter_address, input_ifindex)
    label_replace(xflow_interface_info, "input_ifindex", "$1", "ifindex", "(.+)")
)
```

> [!IMPORTANT]
> `job` and `instance` belong in `on()`: two Prometheus targets scraping one device make the match many-to-many, which fails the whole evaluation. Neither branch may filter `exporter_address!="other"`. A negative matcher also matches a series lacking the label, so the fold row would fall out of both and the total would drop by what the entry bound folded.

## Reloading

`--web.enable-lifecycle` exposes `/-/reload`, which re-reads every enrichment source. A `SIGHUP` does the same without the flag.

- **POST or PUT only**, and unexposed by default, a reload being a write rather than a read — [Endpoints](README.md#endpoints) carries the status contract.
- **A failed reload keeps the previous data** — the set already loaded stays in force, and the endpoint answers 500 with the reason.
- **Every source is attempted** — one source failing does not stop the next, and the answer names every failure.
- **Atomic** — a new set is built whole before it replaces the old one, so no lookup pauses.
- **Only the sources startup opened** — a reload re-reads their files, never the flags.
- **`--dry-run` opens every source** the same way and binds nothing — [Help](help.md#notes) carries what else it checks.

> [!NOTE]
> A list gone missing would otherwise unflag every address at once, which reads as a network that had just gone clean; `xflow_threat_reload_failures_total` counts those loads. The mapping file has no such counter, mirroring the databases: a failed load answers `/-/reload` with 500 and logs its reason. Each mmdb reader is replaced rather than reopened, so a lookup never sees a half-loaded set and the decode path never pauses.
