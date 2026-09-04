# Protocol Support

Every listener accepts every protocol below, identified per datagram. Transport is plaintext UDP.

| Protocol                                                | Status    | Verified on                               |
| :------------------------------------------------------ | :-------- | :---------------------------------------- |
| [NetFlow v5](#netflow-v5) (incl. J-Flow v5)             | Supported | Cisco C891FJ (planned)                    |
| [NetFlow v8](#netflow-v8) (incl. J-Flow v8)             | Supported | Cisco C891FJ (planned)                    |
| [NetFlow v9](#netflow-v9-and-ipfix) (incl. FNF, J-Flow) | Supported | Cisco WS-C2960CX-8PC-L, Cisco C9800-CL-K9 |
| [NetFlow-Lite](#netflow-lite) (packet sections)         | Supported | Awaiting a device                         |
| [IPFIX](#netflow-v9-and-ipfix) / NetFlow v10            | Supported | Cisco C9800-CL-K9                         |
| [sFlow v5](#sflow-v5)                                   | Supported | HP 2530-8G (planned)                      |

- **Cisco WS-C2960CX-8PC-L** — a Catalyst 2960-CX on `C2960CX-UNIVERSALK9-M` 15.2(7)E3, the one device here declaring a sampler, exporting v9 under a custom record that parses a 5-tuple.
- **Cisco C9800-CL-K9** — a Catalyst 9800-CL on `C9800-CL-K9_IOSXE` 17.15.6, exporting IPFIX and NetFlow v9 at once from `record wireless avc basic`, which keys a wireless client rather than a switched port.

> [!NOTE]
> **Verified on** names the vendor and model whose own export this decoder was read against, so synthetic datagrams and unit tests do not count. A row reading `(planned)` names hardware on order rather than hardware measured, leaving that protocol implemented and covered by fixtures but never read off a wire. Neither verified device names an interface, and neither exports a section. The 2960-CX carries a parsed 5-tuple under a custom record, and the 9800-CL keys a wireless client rather than a switched port.

> [!NOTE]
> DTLS is not supported. No shipping network OS exports flows over DTLS, and Go has no production DTLS 1.3 implementation yet.

## Version identification

The protocol is read from the first bytes of every datagram, not from the port it arrived on.

- NetFlow and IPFIX open with a 16-bit version: `0x0005`, `0x0008`, `0x0009`, `0x000A`.
- sFlow opens with a 32-bit version, so an sFlow v5 datagram begins `0x00000005`.
- The two cannot collide — no NetFlow version is `0`, so a zero first half-word can only be sFlow.

## NetFlow v5

The fixed 48-byte record format, shared byte for byte with J-Flow v5. Flow instants are anchored from the device uptime to the export timestamp, and the header's sampling interval rides each record.

### Packet layout

A 24-byte header followed by 1 to 30 fixed records. Trailing bytes past the claimed count are tolerated as padding.

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

### Record layout

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
| 46–47 | `pad2`                  | Padding                               |

## NetFlow v8

Router-aggregated exports, all fourteen methods of aggregation export version 2. A v8 record carries only its method's dimensions — the rest stay absent rather than zero.

### Packet layout

The v5 header through byte 21, then the aggregation selector. The record length is a property of the method, not of the header.

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

| Bytes | Header field  | Notes                                   |
| :---- | :------------ | :-------------------------------------- |
| 0–21  | v5 header     | Version `0x0008`, count, clocks, engine |
| 22    | `aggregation` | Aggregation method, 1–14                |
| 23    | `agg_version` | Must be `2`, the only version shipped   |
| 24–27 | `reserved`    | Padding to the 28-byte header           |

### Aggregation methods

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

Methods 1–5 and 9–14 open with the `dFlows`/`dPkts`/`dOctets` triple and place the flow instants at bytes 12 and 16. The Catalyst methods 6–8 lead with their address fields instead and carry no flow count of their own; method 6 keeps the instants at the common 12 and 16, methods 7 and 8 push them to 16/20 and 20/24.

### Record layout

Method 1, AS aggregation, is the shape the counter-first family shares.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            dFlows                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             dPkts                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            dOctets                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             First                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Last                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            src_as             |            dst_as             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             input             |            output             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Method 8, full flow, is the shape the Catalyst family shares: addresses first, no flow count, and a tail this exporter does not read.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            dstaddr                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            srcaddr                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            dstport            |            srcport            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             dPkts                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            dOctets                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             First                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Last                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            output             |             input             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      tos      |     prot      |           not read            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           not read                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           not read                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## NetFlow v9 and IPFIX

NetFlow v9 and IPFIX are distinct protocols that share one template mechanism, which is why a single section covers both. IPFIX carries `0x000A` in the version field NetFlow numbered up to 9, so it is also called NetFlow v10 — a name the IETF never used. [IPFIX against NetFlow v9](#ipfix-against-netflow-v9) tabulates where the two part company.

Templates are cached per exporter address and Observation Domain ID together, as RFC 7011 requires, and per protocol besides. The pair RFC 7011 names is not enough here: a v9 Source ID, an IPFIX Observation Domain ID and an sFlow sub-agent id are numbered independently over one range, so two collide on any repeated value. The 256 floor RFC 7011 sets is on template ids, not on these, so with the protocol in the key two domains reusing one template ID never corrupt each other.

- A Catalyst 9800-CL exporting v9 and IPFIX at once numbers both protocols' options templates 256 and 257 under domain 1, so one address announces each id twice with different field counts.
- A template declaring a zero-width fixed field, more than `--parser.max-fields-per-template` fields, or specifiers that overrun their set is refused as `invalid_template`.
- A template unrefreshed for `--parser.template-ttl` expires — an orphaned template may describe a schema the device has replaced — and `missing_template` is expected after a restart until each device re-announces.
- IPFIX adds enterprise information elements, bounds-checked variable-length fields, and template withdrawals.

### NetFlow v9 packet layout

A 20-byte header followed by one or more FlowSets. Template and data FlowSets interleave freely, and a data FlowSet is not necessarily preceded by the template it references.

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

The header itself is fixed.

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

| Bytes | Header field    | Notes                                           |
| :---- | :-------------- | :---------------------------------------------- |
| 0–1   | Version         | `0x0009`                                        |
| 2–3   | Count           | FlowSet records, template and data together     |
| 4–7   | System Uptime   | Milliseconds since the device booted            |
| 8–11  | UNIX Seconds    | Export instant, seconds since the epoch         |
| 12–15 | Sequence Number | Export packets sent, not flows                  |
| 16–19 | Source ID       | The Observation Domain ID part of the cache key |

### FlowSets

Every FlowSet opens with a 4-byte header: the FlowSet ID, then the length. The length is TLV — it covers the header, the records and any padding, so it is what locates the next FlowSet.

| FlowSet ID | Contents         | Notes                     |
| :--------- | :--------------- | :------------------------ |
| 0          | Template         | Template FlowSet          |
| 1          | Options template | Options FlowSet           |
| 2–255      | Reserved         | Refused as `reserved_set` |
| ≥ 256      | Data             | ID equals the Template ID |

Padding aligns each FlowSet to a 32-bit boundary and is counted in the length. Trailing bytes shorter than a FlowSet header are padding and are tolerated.

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

### Template and options records

A template record is a Template ID and a Field Count, then that many 4-byte specifiers of Field Type and Field Length. One template FlowSet may carry several template records, which is why the Field Count rather than the FlowSet length ends each record.

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

An options template record replaces the Field Count with two byte lengths: Option Scope Length and Option Length. The specifier counts are those lengths divided by four, and the scope specifiers come first.

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

| Scope value | Scope         | Reported on           |
| :---------- | :------------ | :-------------------- |
| `0x0001`    | System        | The device as a whole |
| `0x0002`    | Interface     | One interface         |
| `0x0003`    | Line Card     | One line card         |
| `0x0004`    | NetFlow Cache | One cache             |
| `0x0005`    | Template      | One template          |

> [!NOTE]
> A zero-length scope field occurs in the wild as a bare system scope, so it is accepted. A zero-length option field is still refused as `invalid_template`.

### Field types

Field types are 16-bit and vendor-assigned. Cisco defines 1–104 consistently across every platform it ships, reserves 105–127, and refers 128–32767 to the IANA IPFIX registry. Counters are declared as a variable width `N`, so `IN_BYTES` is a 32-bit counter on an access router and a 64-bit one on a core router without any format change.

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

The uptime-relative pair 21 and 22 is what classic NetFlow exports; Flexible NetFlow templates may carry the absolute clocks 150–153 instead, and both are read. [`fields.go`](../internal/decoder/fields.go) is authoritative for the full set consumed, and every other type is skipped over by its declared length.

A variable-width integer is read at 1, 2, 4 or 8 octets, and any other width reports nothing rather than a truncation or a zero-extension. A template declaring `INPUT_SNMP` or `OUTPUT_SNMP` three octets wide therefore leaves the interface unread, which `input_ifindex` publishes as `0`.

### IPFIX packet layout

A 16-byte message header, then Sets that frame exactly as v9 FlowSets do.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Version = 10          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Export Time                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Observation Domain ID                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Bytes | Header field          | Notes                                   |
| :---- | :-------------------- | :-------------------------------------- |
| 0–1   | Version               | `0x000A`                                |
| 2–3   | Length                | The whole message, this header included |
| 4–7   | Export Time           | Export instant, seconds since the epoch |
| 8–11  | Sequence Number       | Data records sent, not messages         |
| 12–15 | Observation Domain ID | The domain part of the cache key        |

### IPFIX against NetFlow v9

| Aspect            | NetFlow v9               | IPFIX                         |
| :---------------- | :----------------------- | :---------------------------- |
| Template set ID   | 0                        | 2                             |
| Options set ID    | 1                        | 3                             |
| Reserved set IDs  | 2–255                    | 0–1 and 4–255                 |
| Message length    | Absent, count of records | Bytes 2–3                     |
| Sequence counts   | Export packets           | Data records                  |
| Options head      | Two byte lengths         | Field count, scope count      |
| Enterprise fields | Absent                   | Bit 15 set, then a 4-byte PEN |
| Variable length   | Absent                   | Declared `65535`              |

A variable-length field carries its own length inline: one byte, or `255` followed by a two-byte length where the value exceeds 254 bytes. An IPFIX options template must declare at least one scope field, and the scope fields lead the specifier list.

The enterprise bit is what makes an IPFIX field specifier variable in size.

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

## NetFlow-Lite

Catalyst 2960-X/XR, 2960-CX, 3560-CX and 4948E are documented as shipping one sampled packet section per v9 or IPFIX record. Sections decode through the same header walk the sFlow decoder uses.

- Elements: the deprecated v9 field 104 (`layer2packetSectionData`), and IPFIX `dataLinkFrameSection` (315), `ipHeaderPacketSection` (313), `dataLinkFrameSize` (312).
- The section is walked only where the record carries neither address, so the device's own parse wins; the walk then supplies the addresses, protocol, TOS, ports and flags. One record reads as one sampled packet.
- The 309/310 `samplingSize`/`samplingPopulation` options pair feeds the sampling correction.

| Element                   | ID  | Carries                                     |
| :------------------------ | :-- | :------------------------------------------ |
| `layer2packetSectionData` | 104 | The v9 section, fixed width and zero-padded |
| `dataLinkFrameSection`    | 315 | The IPFIX section, from the Ethernet header |
| `ipHeaderPacketSection`   | 313 | A section that starts at the IP header      |
| `dataLinkFrameSize`       | 312 | The original frame length, before slicing   |

A fixed-width v9 section is zero-padded, so a frame cut before its transport header reads zero ports — and a flags profile of `none` from the padded flags byte — the one ambiguity a padded section cannot escape.

The white paper's own table gives no length for 104, nor for the offset and size elements 102 and 103 beside it, so the section is taken at whatever width the template declares for the field.

> [!IMPORTANT]
> No device available here exports a section, so this path is covered by fixtures alone — the table at the top of this page carries what each decoder has met.

## sFlow v5

Flow samples, compact and expanded, decode from the raw Ethernet header — through stacked VLAN tags to IPv4/IPv6 and the TCP/UDP ports — and from the pre-parsed sampled IPv4/IPv6 records. A sampled header cut short keeps the layers that decoded.

> [!NOTE]
> Counter samples are out of scope: they carry interface statistics, not traffic.

### Datagram layout

Samples nest inside the datagram, and records inside each sample.

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

Every field is a 32-bit XDR word, so offsets shift with the agent address width rather than being fixed.

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

| Field              | Bytes   | Notes                                |
| :----------------- | :------ | :----------------------------------- |
| Version            | 4       | `5`                                  |
| Agent address type | 4       | `1` IPv4, `2` IPv6                   |
| Agent address      | 4 or 16 | Width from the type above            |
| Sub-agent ID       | 4       | Keyed as the observation domain      |
| Sequence number    | 4       | Datagrams sent by this agent         |
| Uptime             | 4       | Milliseconds since the device booted |
| Sample count       | 4       | Samples that follow                  |

Each sample is then a 32-bit type, a 32-bit length, and that many bytes. The top 20 bits of the type are the enterprise number and the low 12 bits the format, so a vendor sample is skipped by the length it declared.

| Format | Sample                   | Handling     |
| :----- | :----------------------- | :----------- |
| 1      | Flow sample              | Decoded      |
| 2      | Counter sample           | Out of scope |
| 3      | Flow sample, expanded    | Decoded      |
| 4      | Counter sample, expanded | Out of scope |

### Flow sample layout

The expanded form widens the source ID and the interface fields from one packed word to two, and is otherwise identical.

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

An interface field is a format and a value rather than a plain index. The compact form packs the format into the top two bits and the value into the low 30; the expanded form spells the two out as separate words, so the compact split must not be applied to it.

| Format | Value        | Read as      |
| :----- | :----------- | :----------- |
| 0      | ifIndex      | The index    |
| 0      | `0x3FFFFFFF` | No interface |
| 1      | Discard code | No interface |
| 2      | Destinations | No interface |

Formats 1 and 2 are defined for an output interface and never for an input one, so a non-zero format on the input side is a nonconformant export. Either way the value is not an interface, and the decoder folds it to `0` rather than publishing a number a device never assigned to a port.

The records follow, each a type, a length and its body, framed exactly as the samples are.

| Format | Flow record       | Handling                         |
| :----- | :---------------- | :------------------------------- |
| 1      | Raw packet header | Decoded through the header walk  |
| 2      | Sampled Ethernet  | Skipped                          |
| 3      | Sampled IPv4      | Decoded, pre-parsed              |
| 4      | Sampled IPv6      | Decoded, pre-parsed              |
| ≥ 1001 | Extended data     | Skipped, it annotates the sample |

A raw packet header record is a header protocol, the original frame length, the stripped byte count, the header length, and then the header itself. Only protocol `1`, Ethernet, is read — any other header protocol is refused and counted `malformed` — and the frame length rather than the captured length is what the byte counter takes.

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

## Options and enrichment

Options templates feed the packet sampling rate, preferred in this order: the PSAMP interval/space pair, the sampler size/population pair, the random-sampler interval, the legacy interval. The rate in force is published as `xflow_sampling_rate`.

| Elements | Pair or value               | Preference |
| :------- | :-------------------------- | :--------- |
| 305, 306 | PSAMP interval and space    | First      |
| 309, 310 | Sampler size and population | Second     |
| 50       | Random-sampler interval     | Third      |
| 34       | Legacy sampling interval    | Last       |

Cisco AVC application tables resolve each record's `applicationId` (IE 95) into the name and category the device itself declared. A vendor that instead embeds the name in the record rides the same string interner, so one name allocates once rather than per flow. A user identity carried beside it is not read: it is high-cardinality and personally identifying, so no series would be allowed to carry it.

- IE 95 is 8 bits of engine ID followed by the selector, and IE 96 carries the name an options record binds to it.
- The category arrives under Cisco's private enterprise number 9 as element 12232, so it is IPFIX-only. It is decoded and held per exporter, and no series carries it: a category label would read `unknown` on every device that exports no AVC.
- A v9 field of 56701 is read as an embedded application name, that number being outside the IANA range and vendor-assigned.

## References

The specifications each decoder is written against.

| Protocol   | Specification                                      |
| :--------- | :------------------------------------------------- |
| NetFlow v5 | [J-Flow v5 Format Output Fields][jflow-v5]         |
| NetFlow v8 | No public spec; see the note below                 |
| NetFlow v9 | [RFC 3954][rfc3954], [Cisco white paper][cisco-v9] |
| J-Flow v9  | [J-Flow v9 Format Output Fields][jflow-v9]         |
| IPFIX      | [RFC 7011][rfc7011], [RFC 7012][rfc7012]           |
| IPFIX file | [RFC 5655][rfc5655]                                |
| sFlow v5   | [sFlow Version 5][sflow5]                          |
| sFlow v4   | [RFC 3176][rfc3176]                                |
| Elements   | [IANA IPFIX Information Elements][iana-ipfix]      |

Four of these need a caveat before they are read as normative.

- **RFC 5655 is the IPFIX _file_ format,** the on-disk serialization of a message stream. The wire protocol this exporter decodes is RFC 7011, which obsoleted RFC 5101; RFC 7012 carries the information model.
- **RFC 3176 is sFlow v4,** Informational and never endorsed by the IETF. sFlow v5 is not an RFC at all — it is the sflow.org specification, and v5 is what this exporter decodes.
- **The Cisco white paper covers v9 alone,** despite the version 5, 8 and 9 title it is usually cited under. It is the format of record for the v9 header, FlowSets and field-type numbers, and for nothing earlier.
- **NetFlow v8 has no public format document.** The aggregation record layouts above come from the flow-tools reference structures, which is what [`netflow8.go`](../internal/decoder/netflow8.go) mirrors.

J-Flow v5 is the Cisco v5 record byte for byte, and Juniper documents the field list without offsets. J-Flow v9 is NetFlow v9 with one Juniper reading: the Source ID names the exporting PIC by its IFD SNMP index, where Cisco splits the same word into engine type and engine ID.

[cisco-v9]: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
[rfc3954]: https://datatracker.ietf.org/doc/html/rfc3954
[rfc7011]: https://datatracker.ietf.org/doc/html/rfc7011
[rfc7012]: https://datatracker.ietf.org/doc/html/rfc7012
[rfc5655]: https://datatracker.ietf.org/doc/rfc5655/
[rfc3176]: https://datatracker.ietf.org/doc/html/rfc3176
[sflow5]: https://sflow.org/sflow_version_5.txt
[jflow-v5]: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/flowmonitoring-output-formats-version5-solutions.html
[jflow-v9]: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/flowmonitoring-output-formats-version9-solutions.html
[iana-ipfix]: https://www.iana.org/assignments/ipfix/ipfix.xhtml
