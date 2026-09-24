# Protocols

This documentation provides an overview of the supported protocols and their verification matrix.

## Verification Matrix

Each row records one protocol decoded from the device's own export, on the release it ran.

| Device                 | Software release | Protocol   | Verified export profile                    |
| :--------------------- | :--------------- | :--------- | :----------------------------------------- |
| Cisco C891FJ-K9        | `IOS 15.9(3)M13` | NetFlow v5 | Main cache, Random Sampled NetFlow         |
| Cisco C891FJ-K9        | `IOS 15.9(3)M13` | NetFlow v8 | Aggregation caches, methods 1–5 and 9–14   |
| Cisco C891FJ-K9        | `IOS 15.9(3)M13` | NetFlow v9 | Main and `bgp-nexthop-tos` caches          |
| Cisco C891FJ-K9        | `IOS 15.9(3)M13` | NetFlow v9 | Flexible NetFlow monitor, custom record    |
| Cisco WS-C2960CX-8PC-L | `IOS 15.2(7)E3`  | NetFlow v9 | Custom record, two samplers declared       |
| Cisco C9800-CL-K9      | `IOS-XE 17.15.6` | NetFlow v9 | `record wireless avc basic`                |
| Cisco C9800-CL-K9      | `IOS-XE 17.15.6` | IPFIX      | `record wireless avc basic`                |
| HP 2530-8G             | `YA.16.11.0030`  | sFlow v5   | Compact flow samples, 1-in-50 and 1-in-100 |

## Version Identification

The protocol is resolved from a datagram's leading bytes, not from the port it arrived on.

| Offset | Width  | Value        | Protocol   |
| :----- | :----- | :----------- | :--------- |
| 0–1    | 16-bit | `0x0005`     | NetFlow v5 |
| 0–1    | 16-bit | `0x0008`     | NetFlow v8 |
| 0–1    | 16-bit | `0x0009`     | NetFlow v9 |
| 0–1    | 16-bit | `0x000A`     | IPFIX      |
| 0–3    | 32-bit | `0x00000005` | sFlow v5   |

## NetFlow v5

The fixed 48-byte record format, **shared byte for byte with J-Flow v5.**

Flow instants are anchored from the device uptime to the export timestamp. That uptime is a 32-bit millisecond counter, so an instant is taken as a modular age and a flow straddling its 49.7-day wrap keeps its duration. The header's sampling interval rides each record.

Where that interval is zero, the second pad field is read as the sampler the record names. The format carries no rate for it — v5 has no options record to declare one — so the counts stay uncorrected and `xflow_sampling_unresolved_flows_total` says so. A zero there is the absence of a sampler and is left alone.

<details><summary><b>Packet Layout</b></summary><p>

| Bytes | Header field        | Notes                                    |
| :---- | :------------------ | :--------------------------------------- |
| 0–1   | `version`           | `0x0005`                                 |
| 2–3   | `count`             | Records in this datagram, 1–30           |
| 4–7   | `SysUptime`         | Milliseconds since the device booted     |
| 8–11  | `unix_secs`         | Export instant, seconds since the epoch  |
| 12–15 | `unix_nsecs`        | Residual nanoseconds of the same instant |
| 16–19 | `flow_sequence`     | Running count of records exported        |
| 20    | `engine_type`       | Switching engine type                    |
| 21    | `engine_id`         | Switching engine slot                    |
| 22–23 | `sampling_interval` | 2-bit mode, then the 14-bit interval     |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Version = 5          |             Count             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SysUptime                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           unix_secs                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          unix_nsecs                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         flow_sequence                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  engine_type  |   engine_id   |       sampling_interval       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

<details><summary><b>Record Layout</b></summary><p>

| Bytes | Record field            | Notes                                 |
| :---- | :---------------------- | :------------------------------------ |
| 0–7   | `srcaddr` / `dstaddr`   | Four bytes each                       |
| 8–11  | `nexthop`               | Not published by this exporter        |
| 12–15 | `input` / `output`      | SNMP ifIndex, two bytes each          |
| 16–23 | `dPkts` / `dOctets`     | Four bytes each                       |
| 24–31 | `first` / `last`        | `SysUptime` at the first, last packet |
| 32–35 | `srcport` / `dstport`   | Two bytes each                        |
| 36    | `pad1`                  | Padding                               |
| 37    | `tcp_flags`             | Cumulative OR of the flow's flags     |
| 38–39 | `prot` / `tos`          | IP protocol, then the ToS byte        |
| 40–43 | `src_as` / `dst_as`     | Two bytes each                        |
| 44–45 | `src_mask` / `dst_mask` | Prefix lengths in bits                |
| 46–47 | `pad2`                  | Padding, or the sampler id if sampled |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            srcaddr                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            dstaddr                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            nexthop                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             input             |            output             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             dPkts                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            dOctets                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             first                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             last                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            srcport            |            dstport            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     pad1      |   tcp_flags   |     prot      |      tos      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            src_as             |            dst_as             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   src_mask    |   dst_mask    |             pad2              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

> [!NOTE]
>
> **C891FJ-K9 on 15.9(3)M13** running Random Sampled NetFlow leaves that interval zero and names its sampler in `pad2` instead, so the rate it sampled at reaches no collector. Its counts then read low by that rate, which only the device's own `show flow-sampler` resolves.

## NetFlow v8

The router-aggregated record format. It implements aggregation version 2 covering methods 1 through 14.

An aggregation cache is fed directly from the main cache. Consequently, every enabled method re-reports traffic the main cache already exported. The aggregation method functions as the observation domain here to keep readings isolated.

Summing these caches counts one flow multiple times. A device exporting an aggregated cache as v9 or IPFIX marks it with IE 3, which routes that cache the same way this format is routed. Always send only one view to a collector.

<details><summary><b>Packet Layout</b></summary><p>

| Bytes | Header field  | Notes                                   |
| :---- | :------------ | :-------------------------------------- |
| 0–21  | v5 header     | Version `0x0008`, count, clocks, engine |
| 22    | `aggregation` | Aggregation method, 1–14                |
| 23    | `agg_version` | Must be `2`, the only version shipped   |
| 24–27 | `reserved`    | Padding to the 28-byte header           |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Version = 8          |             Count             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SysUptime                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           unix_secs                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          unix_nsecs                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         flow_sequence                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  engine_type  |   engine_id   |  aggregation  |  agg_version  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           reserved                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

<details><summary><b>Packet Layout - Aggregation Methods</b></summary><p>

###

| Method | Aggregation                   | Record bytes |
| :----- | :---------------------------- | :----------- |
| 1      | AS                            | 28           |
| 2      | Protocol and port             | 28           |
| 3      | Source prefix                 | 32           |
| 4      | Destination prefix            | 32           |
| 5      | Prefix                        | 40           |
| 6      | Destination (Catalyst)        | 32           |
| 7      | Source-destination (Catalyst) | 40           |
| 8      | Full flow (Catalyst)          | 44           |
| 9      | ToS and AS                    | 32           |
| 10     | ToS, protocol and port        | 32           |
| 11     | ToS and source prefix         | 32           |
| 12     | ToS and destination prefix    | 32           |
| 13     | ToS and prefix                | 40           |
| 14     | ToS, prefix and port          | 40           |

</p></details>

## NetFlow v9

The template-based record format. A template declares the fields a data record carries, and the two flowset kinds interleave freely within one datagram.

The template cache is keyed on `(exporter_address, protocol, observation_domain_id, source_port)`. A **Cisco C9800-CL-K9** exporting IPFIX and NetFlow v9 from one address announces options templates 256 and 257 under observation domain 1 in both. A key without the protocol therefore resolves one protocol's record against the other's layout.

A **Cisco C891FJ-K9** runs its traditional cache and a Flexible NetFlow monitor as two export processes under Source ID 0, each from a source port of its own. Each numbers its templates independently, and the monitor took the next ID for each layout it exported, so the two collided on 257 and later on 258. The device breaks the uniqueness RFC 3954 section 9 expects per exporter and domain, so only the session tells the two layouts apart.

A data flowset arriving before its template counts `missing_template` and is dropped, and a clock change on the device leaves its templates in place. RFC 3954 section 9 recommends holding such records and flushing templates on a clock change. Held records are memory a forged sender can fill, and a flush on every NTP step would make each device's next records miss their templates.

A template the parser refuses counts `invalid_template` and still withdraws the layout its ID held, since RFC 3954 section 9 and RFC 7011 section 8.4 have a new template replace the old. The ID's data then counts `missing_template` until a template the parser reads arrives.

IE 61 carries the observation point, `0` for ingress and `1` for egress. RFC 5102 defines no other value, so anything else leaves the point unknown, as does a template omitting the element.

```text
+------------------------+
|     Packet Header      |  20 bytes
+------------------------+
|    Template FlowSet    |  id 0, may be absent
+------------------------+
|      Data FlowSet      |  id >= 256
+------------------------+
|      Data FlowSet      |
+------------------------+
|          ...           |
+------------------------+
|    Template FlowSet    |  templates and data interleave freely
+------------------------+
|      Data FlowSet      |
+------------------------+
```

<details><summary><b>Packet Layout - Header</b></summary><p>

A 20-byte header precedes one or more FlowSets. Template and data FlowSets interleave freely. Consequently, a data FlowSet may arrive before its corresponding template.

| Bytes | Header field    | Notes                                           |
| :---- | :-------------- | :---------------------------------------------- |
| 0–1   | Version         | `0x0009`                                        |
| 2–3   | Count           | FlowSet records, template and data together     |
| 4–7   | System Uptime   | Milliseconds since the device booted            |
| 8–11  | UNIX Seconds    | Export instant, seconds since the epoch         |
| 12–15 | Sequence Number | Export packets sent, not flows                  |
| 16–19 | Source ID       | The Observation Domain ID part of the cache key |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Version = 9          |             Count             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         System Uptime                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         UNIX Seconds                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Source ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

<details><summary><b>Packet Layout - Data Flowsets</b></summary><p>

Every FlowSet opens with a 4-byte header comprising the FlowSet ID and the TLV length. This length covers the header, records, and any padding, allowing the decoder to locate the next FlowSet.

| FlowSet ID | Contents         | Notes                     |
| :--------- | :--------------- | :------------------------ |
| 0          | Template         | Template FlowSet          |
| 1          | Options template | Options FlowSet           |
| 2–255      | Reserved         | Refused as `reserved_set` |
| ≥ 256      | Data             | ID equals the Template ID |

RFC 3954 asks the exporter to pad data and options FlowSets to a 32-bit boundary, which every NetFlow v9 device in the verification matrix omits, so the decoder follows each length as given. Trailing bytes shorter than a FlowSet header are treated as padding and safely ignored.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   FlowSet ID = Template ID    |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~             Record 1, as the template lays it out             ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                  further records, to Length                   ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                 Padding to a 32-bit boundary                  ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

<details><summary><b>Packet Layout - Template FlowSet</b></summary><p>

A template record contains a Template ID and a Field Count, followed by 4-byte specifiers comprising Type and Length. A single FlowSet may carry multiple template records. Therefore, the Field Count strictly demarcates each record's boundary.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        FlowSet ID = 0         |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Template ID          |        Field Count = N        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Field 1 Type          |        Field 1 Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                      N field specifiers                       ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Field N Type          |        Field N Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~              further template records, to Length              ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Options templates replace the Field Count with Option Scope Length and Option Length. These lengths are four times their respective specifier counts. Scope specifiers always precede option specifiers.

| Scope value | Scope         | Reported on           |
| :---------- | :------------ | :-------------------- |
| `0x0001`    | System        | The device as a whole |
| `0x0002`    | Interface     | One interface         |
| `0x0003`    | Line Card     | One line card         |
| `0x0004`    | NetFlow Cache | One cache             |
| `0x0005`    | Template      | One template          |

> [!NOTE]
> A zero-length scope field occurs in the wild as a bare system scope, so it is accepted. A zero-length option field is still refused as `invalid_template`.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        FlowSet ID = 1         |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Template ID          |      Option Scope Length      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Option Length         |         Scope 1 Type          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Scope 1 Length         |        next specifier         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~           scope specifiers, then option specifiers            ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                 Padding to a 32-bit boundary                  ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

<details><summary><b>Packet Layout - Field Types</b></summary><p>

Field types are 16-bit and vendor-assigned. Cisco defines types 1–104, reserves 105–127, and defers 128–32767 to the IANA IPFIX registry. Counters use a variable width `N`, allowing `IN_BYTES` to scale smoothly between 32-bit and 64-bit architectures.

| Type    | Name                                                | Length       |
| :------ | :-------------------------------------------------- | :----------- |
| 1, 2    | `IN_BYTES`, `IN_PKTS`                               | N, default 4 |
| 4–6     | `PROTOCOL`, `SRC_TOS`, `TCP_FLAGS`                  | 1 each       |
| 7, 11   | `L4_SRC_PORT`, `L4_DST_PORT`                        | 2 each       |
| 8, 12   | `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`                    | 4 each       |
| 9, 13   | `SRC_MASK`, `DST_MASK`                              | 1 each       |
| 10, 14  | `INPUT_SNMP`, `OUTPUT_SNMP`                         | N, default 2 |
| 16, 17  | `SRC_AS`, `DST_AS`                                  | N, default 2 |
| 21, 22  | `LAST_SWITCHED`, `FIRST_SWITCHED`                   | 4 each       |
| 23, 24  | `OUT_BYTES`, `OUT_PKTS`                             | N, default 4 |
| 27, 28  | `IPV6_SRC_ADDR`, `IPV6_DST_ADDR`                    | 16 each      |
| 29, 30  | `IPV6_SRC_MASK`, `IPV6_DST_MASK`                    | 1 each       |
| 34, 50  | `SAMPLING_INTERVAL`, `FLOW_SAMPLER_RANDOM_INTERVAL` | 4 each       |
| 150–153 | `flowStart`/`flowEnd`, seconds and milliseconds     | 4, 8         |

Classic NetFlow exports uptime-relative clocks (21, 22). Flexible NetFlow may export absolute clocks (150–153) instead, which win over the uptime pair only with both ends present, a zero among them reading as unset rather than as the epoch. [`fields.go`](../internal/decoder/fields.go) defines all consumed fields; any undeclared type is skipped using its specified length.

RFC 7011 section 9 requires a collector to note every element it does not read, so a template carrying an undeclared type is logged at `info` when it arrives or changes layout. A refresh repeating a logged layout logs nothing. The lines stop at 60 a minute because a forged sender can change a layout with every datagram, and a withheld layout is logged on its next refresh, each line counting those withheld before it.

Variable-width integers are read at any width from 1 to 8 octets. A wider or empty field is left unread rather than truncated, so an interface carried that way reads `0`.

</p></details>

## IPFIX

The IETF standard based on NetFlow v9. It encodes `0x000A` (10) as the version, introducing variable-length fields and enterprise extensions.

It utilizes a 16-byte message header followed by Sets framed identically to v9 FlowSets.

<details><summary><b>The Differences Against NetFlow v9</b></summary><p>

Variable-length fields carry inline lengths: one byte typically, or `255` followed by a two-byte length for larger payloads. Options templates must declare at least one scope field, positioned first. The enterprise bit explicitly controls the variable size of field specifiers.

Reduced-size encoding narrows an integer element to any width its value fits, so an odd width carries a reading like the rest. The `dateTime` types are excluded from it and hold their native width, a narrower field landing in 1970 rather than on the instant the device measured.

A field count of zero is a template withdrawal. UDP gives no ordering, so a withdrawal is ignored and the set is walked past its four octets, leaving announcements behind it readable. A data set whose template is known carries at least one record, so a shorter body counts `malformed` instead of passing as padding.

A malformed message is discarded whole, as RFC 7011 section 9.1 requires, so each set is checked against the message and each data record against its set before anything in the message takes effect. Such a message counts one `malformed` and no `invalid_template`, yet an ID it redefines or refuses is withdrawn all the same unless a set or message length ahead of it breaks the framing. The device's next data then count `missing_template` rather than decode against the layout it left.

A device whose messages keep arriving malformed is still read. RFC 7011 section 9.1 advises stopping, but on UDP that is a switch a forged sender could flip for a real one.

| Aspect            | NetFlow v9               | IPFIX                          |
| :---------------- | :----------------------- | :----------------------------- |
| Template set ID   | 0                        | 2                              |
| Options set ID    | 1                        | 3                              |
| Reserved set IDs  | 2–255                    | 0–1 and 4–255                  |
| Message length    | Absent, count of records | Bytes 2–3                      |
| Sequence counts   | Export packets           | Data records                   |
| Options head      | Two byte lengths         | Field count, scope count       |
| Enterprise fields | Absent                   | Bit 15 set, then a 4-byte PEN  |
| Variable length   | Absent                   | Declared `65535`               |
| Integer widths    | Native only              | Reduced to any width that fits |
| Uptime anchor     | Header `SysUptime`       | Record IE 160                  |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|E|   Information Element ID    |         Field Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~              Enterprise Number, only when E = 1               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

## sFlow v5

The packet-sampling based record format. It relies on standard XDR encoding for all fields.

Flow samples decode from the raw Ethernet header up to transport layers, alongside pre-parsed IPv4/IPv6 records.

The observation point is derived rather than exported. A sample whose interface data source matches the input alone was seen entering the device, one matching the output alone leaving it, and anything else leaves the point unknown.

```text
sFlow v5 datagram
 |
 +-- datagram header
 |
 +-- sample [1..n]       <- type (32) + length (32), then the body
      |
      +-- sample header  <- rate, pool, drops, input, output
      |
      +-- record [1..m]  <- type (32) + length (32), then the body
           |
           +-- raw packet header, or a pre-parsed IPv4/IPv6 record
```

<details><summary><b>Packet Layout</b></summary><p>

Every field is a 32-bit XDR word, so offsets shift with the agent address width.

| Field              | Bytes   | Notes                                |
| :----------------- | :------ | :----------------------------------- |
| Version            | 4       | `5`                                  |
| Agent address type | 4       | `1` IPv4, `2` IPv6                   |
| Agent address      | 4 or 16 | Width from the type above            |
| Sub-agent ID       | 4       | Keyed as the observation domain      |
| Sequence number    | 4       | Datagrams sent by this agent         |
| Uptime             | 4       | Milliseconds since the device booted |
| Sample count       | 4       | Samples that follow                  |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Version = 5                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Agent Address Type                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                 Agent Address, 4 bytes or 16                  ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sub-Agent ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Uptime                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sample Count                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

</p></details>

<details><summary><b>Flow Sample Layout</b></summary><p>

Each sample comprises a 32-bit type, a 32-bit length, and the payload body. The type encodes the enterprise number (top 20 bits) and format (low 12 bits). Vendor samples are securely skipped using their declared length.

| Format | Sample                   | Handling     |
| :----- | :----------------------- | :----------- |
| 1      | Flow sample              | Decoded      |
| 2      | Counter sample           | Out of scope |
| 3      | Flow sample, expanded    | Decoded      |
| 4      | Counter sample, expanded | Out of scope |

The expanded form widens the source ID and interface fields into two words. It is otherwise structurally identical to the compact form.

| Field            | Compact | Expanded |
| :--------------- | :------ | :------- |
| Sequence number  | 4       | 4        |
| Source ID        | 4       | 8        |
| Sampling rate    | 4       | 4        |
| Sample pool      | 4       | 4        |
| Drops            | 4       | 4        |
| Input interface  | 4       | 8        |
| Output interface | 4       | 8        |
| Record count     | 4       | 4        |

Interface fields encode both a format and a value. The compact form packs these into a single word (2-bit format, 30-bit value). The expanded form separates them into two distinct words, requiring independent parsing logic.

| Format | Value        | Read as      |
| :----- | :----------- | :----------- |
| 0      | ifIndex      | The index    |
| 0      | `0x3FFFFFFF` | No interface |
| 1      | Discard code | No interface |
| 2      | Destinations | No interface |

Formats 1 and 2 represent discard codes or destinations, exclusive to output interfaces. A non-zero format on an input interface indicates a nonconformant export. The decoder safely folds these non-interface values to `0` to prevent invalid port assignments.

Records immediately follow the sample header. Each record is framed with a type, length, and body, matching the sample structure.

| Format | Flow record       | Handling                         |
| :----- | :---------------- | :------------------------------- |
| 1      | Raw packet header | Decoded through the header walk  |
| 2      | Sampled Ethernet  | Skipped                          |
| 3      | Sampled IPv4      | Decoded, pre-parsed              |
| 4      | Sampled IPv6      | Decoded, pre-parsed              |
| ≥ 1001 | Extended data     | Skipped, it annotates the sample |

Pre-parsed records (formats 3/4) report IP packet lengths, deliberately excluding encapsulation bytes. Extended records (formats 1001-1003) annotate samples with VLANs, next hops, or AS paths. These annotations are decoded but currently do not feed any metric series.

Raw packet headers contain the header protocol, original frame length, stripped byte count, and the captured header. Ethernet (1) walks the frame, and IPv4 (11) and IPv6 (12) walk the packet directly. The enum runs to 14 and a receiver must tolerate values beyond it, so any other layer counts `unsupported_header_protocol` rather than `malformed`.

The byte counter strictly utilizes the original wire frame length, inclusive of FCS. Every packet-describing record in one sample describes the same sampled packet, so a sample yields one flow record. The raw header is the preferred format and wins where a device sends it alongside a pre-parsed twin.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Header Protocol                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Frame Length                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Stripped                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Header Length = L                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                    Header bytes, L of them                    ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The declared header length equals the captured frame length rounded up to a 4-byte boundary, capped by the configured maximum. Flow samples independently carry their sampler's drop counter. Multiple samplers within one datagram will legitimately report disparate drop counts.

</p></details>

## Packet Sections

Records substituting parsed flow fields with sampled packet sections decode via the sFlow header walk.

Sections consume the exact byte width declared by their template. Fixed-width v9 sections are inherently zero-padded. Consequently, frames truncated before the transport header inadvertently yield zero ports and empty TCP flags.

**NetFlow Lite carries no section.** Cisco's overview states Catalyst switches (e.g., 2960-X) classify packets in hardware and strictly sample on ingress. Consequently, output collections on these platforms silently report `0` for all unicast flows.

| Element                   | ID  | Carries                                     |
| :------------------------ | :-- | :------------------------------------------ |
| `layer2packetSectionData` | 104 | The v9 section, fixed width and zero-padded |
| `dataLinkFrameSection`    | 315 | The IPFIX section, from the Ethernet header |
| `ipHeaderPacketSection`   | 313 | A section that starts at the IP header      |
| `dataLinkFrameSize`       | 312 | The original frame length, before slicing   |

## References

For full protocol layouts, refer to official vendor specifications.

| Protocol          | Specification                                      |
| :---------------- | :------------------------------------------------- |
| J-Flow v5         | [J-Flow v5 Format Output Fields][jflow-v5]         |
| NetFlow v8        | No public specification                            |
| NetFlow v9        | [RFC 3954][rfc3954], [Cisco white paper][cisco-v9] |
| J-Flow v9         | [J-Flow v9 Format Output Fields][jflow-v9]         |
| IPFIX Protocol    | [RFC 7011][rfc7011], [RFC 7012][rfc7012]           |
| IPFIX File Format | [RFC 5655][rfc5655]                                |
| sFlow v5          | [sFlow Version 5][sflow5]                          |

[rfc3954]: https://datatracker.ietf.org/doc/html/rfc3954
[rfc7011]: https://datatracker.ietf.org/doc/html/rfc7011
[rfc7012]: https://datatracker.ietf.org/doc/html/rfc7012
[rfc5655]: https://datatracker.ietf.org/doc/rfc5655/
[sflow5]: https://sflow.org/sflow_version_5.txt
[jflow-v5]: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/flowmonitoring-output-formats-version5-solutions.html
[jflow-v9]: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/flowmonitoring-output-formats-version9-solutions.html
[cisco-v9]: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
