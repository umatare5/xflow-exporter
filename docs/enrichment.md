# Enrichment

This documentation provides an overview of the enrichments supported by the xflow-exporter.

## Sources

An `--enrich.*` source provides additional context to the flow records.

The following table summarizes the enrichment sources:

| Flag                        | Fills                                    | Feeds to            |
| :-------------------------- | :--------------------------------------- | :------------------ |
| `--enrich.asn-database`     | The AS numbers, from a MaxMind-format DB | BGP AS              |
| `--enrich.country-database` | The ISO country codes, from the same     | Countries           |
| `--enrich.mapping-file`     | Device, interface, VLAN and port names   | Applications, VLANs |
| `--enrich.services`         | The application, from the transport port | Applications        |
| `--enrich.threat-file`      | A flag on addresses a list file names    | Threats             |

> [!NOTE]
>
> Reloading via the `/-/reload` endpoint or `SIGHUP` signal triggers a reload of these enrichment files.

> [!TIP]
>
> The following two scripts help you to gather the necessary enrichment files:
>
> - [`scripts/fetch-enrichment-data.sh`](../scripts/fetch-enrichment-data.sh) — fetch the enrichment data for BGP AS, Countries and Threats.
> - [`scripts/fetch-device-names.sh`](../scripts/fetch-device-names.sh) — scrape the device information for Hosts, VLANs over SNMP and write out it.

## Databases

`--enrich.asn-database` and `--enrich.country-database` loads MaxMind-format GeoLite2/DB-IP files.

This populates AS numbers and ISO country codes where omitted by the device. Lookups resolve dynamically.

## Mapping File

`--enrich.mapping-file` labels devices, interfaces, VLANs, and extra transport ports.

See [`examples/mapping.yml`](../examples/mapping.yml) for the example with the detailed configuration comments.

## Service Names

`--enrich.services` maps standard protocol ports to application names using the internal tables.

The same two tables also decide which port keys `xflow_service_*` and `xflow_destination_*`, whether or not `--enrich.services` is set. A port the mapping file declares moves that service's reply leg onto its own entry, from the next entry created.

The built-in table names around fifty ports and no internal service, so a site's own listeners reach the service end of a key through the mapping file alone. A symmetric pair keys on its destination, and a port declared inside 1024–4999 takes the service end off a client that reused it.

Resolution order is first match wins.

1. Use name on the flow record itself
2. Use `--enrich.mapping-file` `services:` block
3. Use `--enrich.services` built-in table
4. No name

## Threat Lists

`--enrich.threat-file` parses flat text files containing IP addresses. Hit on either source or destination triggers a threat record.

The format is one address per line as shown below. The blank lines, # and ; comments and trailing fields are skipped.

```text
192.0.2.1
198.51.100.1
203.0.113.1
# This is a comment
; This is also a comment
```
