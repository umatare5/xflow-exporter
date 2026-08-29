# Protocol Support

Every listener accepts every protocol below, identified per datagram. Transport is plaintext UDP.

| Protocol                       | Status    |
| :----------------------------- | :-------- |
| NetFlow v5 (incl. J-Flow v5)   | Supported |
| NetFlow v8 (incl. J-Flow v8)   | Supported |
| NetFlow v9 (incl. FNF, J-Flow) | Supported |
| NetFlow-Lite (packet sections) | Supported |
| IPFIX / NetFlow v10            | Supported |
| sFlow v5                       | Supported |

> [!Note]
> DTLS is not supported. No shipping network OS exports flows over DTLS, and Go has no production DTLS 1.3 implementation yet.

## NetFlow v5

The fixed 48-byte record format, shared byte for byte with J-Flow v5. Flow instants are anchored from the device uptime to the export timestamp, and the header's sampling interval rides each record.

## NetFlow v8

Router-aggregated exports, all fourteen methods of aggregation export version 2. A v8 record carries only its method's dimensions — the rest stay absent rather than zero.

## NetFlow v9 and IPFIX

Templates are cached per exporter address and Observation Domain ID together, as RFC 7011 requires. Two domains reusing one template ID therefore never corrupt each other.

- A template declaring a zero-width fixed field, or more than `--parser.max-fields-per-template` fields, is refused as `invalid_template`.
- A template unrefreshed for `--parser.template-ttl` expires, and `missing_template` is expected after a restart until each device re-announces.
- IPFIX adds enterprise information elements, bounds-checked variable-length fields, and template withdrawals.

## NetFlow-Lite

Catalyst 2960-X/XR, 2960-CX, 3560-CX and 4948E ship one sampled packet section per v9 or IPFIX record. Sections decode through the same header walk the sFlow decoder uses.

- Elements: the deprecated v9 field 104 (`layer2packetSectionData`, the measured device behaviour), and IPFIX `dataLinkFrameSection` (315), `ipHeaderPacketSection` (313), `dataLinkFrameSize` (312).
- Fields the device parsed itself win over the section, and one record reads as one sampled packet.
- The 309/310 `samplingSize`/`samplingPopulation` options pair feeds the sampling correction.

## sFlow v5

Flow samples, compact and expanded, decode from the raw Ethernet header — through stacked VLAN tags to IPv4/IPv6 and the TCP/UDP ports — and from the pre-parsed sampled IPv4/IPv6 records. A sampled header cut short keeps the layers that decoded.

> [!Note]
> Counter samples are out of scope: they carry interface statistics, not traffic.

## Options and enrichment

Options templates feed the packet sampling rate, preferred in this order: the PSAMP interval/space pair, the sampler size/population pair, the random-sampler interval, the legacy interval. The rate in force is published as `xflow_sampling_rate`.

Cisco AVC application tables resolve each record's `applicationId` (IE 95) into the name and category the device itself declared. PAN-OS App-ID and User-ID strings ride v9 records through a string interner, so one name allocates once rather than per flow.
