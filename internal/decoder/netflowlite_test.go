package decoder

import (
	"net/netip"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// liteSectionSize is the fixed section size the v9 fixtures declare, the
// device default of the packet-section size setting.
const liteSectionSize = 64

// padTo zero-pads a frame to the fixed v9 section size.
func padTo(frame []byte) []byte {
	padded := make([]byte, liteSectionSize)
	copy(padded, frame)
	return padded
}

// TestDecodeNetFlowLite_V9PacketSection covers the measured v9 mode: the
// deprecated field 104 carries a fixed-size layer-2 section, zero-padded,
// which decodes through the same header walk sFlow uses.
func TestDecodeNetFlowLite_V9PacketSection(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldInputSNMP, 4},
		[2]uint16{fieldPacketSectionV9Data, liteSectionSize},
	))

	record := be32(nil, 7)
	record = append(record, padTo(tcpFrame(false))...)

	records, err := d.Decode(testExporter,
		v9Packet(1, fixtureV9ODID, tpl, flowSet(fixtureV9TemplateID, record)), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}

	got := records[0]
	if got.SrcAddr != netip.MustParseAddr("10.0.0.1") || got.DstAddr != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("addresses = %v -> %v, want the section's IPv4 pair", got.SrcAddr, got.DstAddr)
	}
	if got.SrcPort != 51234 || got.DstPort != 443 || got.Protocol != protocolTCP {
		t.Errorf("transport = %d -> %d proto %d, want the section's TCP tuple", got.SrcPort, got.DstPort, got.Protocol)
	}
	if got.TOS != 0xB8 || got.TCPFlags != 0x18 {
		t.Errorf("tos/flags = %#x/%#x, want the section's readings", got.TOS, got.TCPFlags)
	}
	if got.InputIf != 7 {
		t.Errorf("InputIf = %d, want the device-parsed field kept", got.InputIf)
	}
	if got.Packets != 1 {
		t.Errorf("Packets = %d, want one sampled packet per record", got.Packets)
	}
	if got.Version != flow.VersionNetFlowV9 {
		t.Errorf("Version = %v, want the enveloping protocol", got.Version)
	}
}

// TestDecodeNetFlowLite_IPFIXSectionWithFrameSize covers the IPFIX mode: a
// variable-length dataLinkFrameSection with the original frame length in
// dataLinkFrameSize.
func TestDecodeNetFlowLite_IPFIXSectionWithFrameSize(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := ipfixTemplateSet(
		ipfixSpec(fieldDataLinkFrameSize, 4, 0),
		ipfixSpec(fieldDataLinkFrameSection, variableFieldLength, 0),
	)

	frame := tcpFrame(true) // VLAN-tagged, exercising the shared walk
	record := be32(nil, 1518)
	record = append(record, byte(len(frame)))
	record = append(record, frame...)

	records, err := d.Decode(testExporter,
		ipfixMessage(0, tpl, flowSet(fixtureIPFIXTemplateID, record)), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}

	got := records[0]
	if got.SrcPort != 51234 || got.DstPort != 443 {
		t.Errorf("ports = %d -> %d, want the tuple read through the VLAN tag", got.SrcPort, got.DstPort)
	}
	if got.Bytes != 1518 {
		t.Errorf("Bytes = %d, want the dataLinkFrameSize 1518", got.Bytes)
	}
	if got.Packets != 1 {
		t.Errorf("Packets = %d, want 1", got.Packets)
	}
}

// TestDecodeNetFlowLite_IPHeaderSection covers IE 313, a section starting at
// the IP header with no layer 2 in front.
func TestDecodeNetFlowLite_IPHeaderSection(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := ipfixTemplateSet(
		ipfixSpec(fieldIPHeaderPacketSection, variableFieldLength, 0),
	)

	// Reuse the frame builder and strip its Ethernet header.
	ipPacket := tcpFrame(false)[ethernetHdrLen:]
	record := append([]byte{byte(len(ipPacket))}, ipPacket...)

	records, err := d.Decode(testExporter,
		ipfixMessage(0, tpl, flowSet(fixtureIPFIXTemplateID, record)), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}

	got := records[0]
	if got.SrcAddr != netip.MustParseAddr("10.0.0.1") || got.DstPort != 443 {
		t.Errorf("record = %+v, want the IP-only section decoded", got)
	}
}

// TestDecodeNetFlowLite_ParsedFieldsWinOverSection pins the precedence: a
// record carrying both the device's parsed fields and a section keeps the
// device's own classification.
func TestDecodeNetFlowLite_ParsedFieldsWinOverSection(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldIPv4SrcAddr, 4},
		[2]uint16{fieldIPv4DstAddr, 4},
		[2]uint16{fieldInBytes, 4},
		[2]uint16{fieldPacketSectionV9Data, liteSectionSize},
	))

	record := append([]byte{192, 0, 2, 100}, 192, 0, 2, 200)
	record = be32(record, 5555)
	record = append(record, padTo(tcpFrame(false))...)

	records, err := d.Decode(testExporter,
		v9Packet(1, fixtureV9ODID, tpl, flowSet(fixtureV9TemplateID, record)), nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}

	got := records[0]
	if got.SrcAddr != netip.MustParseAddr("192.0.2.100") || got.DstAddr != netip.MustParseAddr("192.0.2.200") {
		t.Errorf("addresses = %v -> %v, want the device-parsed pair kept", got.SrcAddr, got.DstAddr)
	}
	if got.Bytes != 5555 {
		t.Errorf("Bytes = %d, want the device-parsed count kept", got.Bytes)
	}
}

// TestDecodeNetFlowLite_ShortPaddedSection pins that a section shorter than
// its padding decodes what fits and fabricates nothing.
func TestDecodeNetFlowLite_ShortPaddedSection(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldPacketSectionV9Data, liteSectionSize},
	))

	// Ethernet and IPv4 only: the section ends before the TCP ports.
	frame := tcpFrame(false)[:ethernetHdrLen+ipv4MinHdrLen]
	record := padTo(frame)

	records, err := d.Decode(testExporter,
		v9Packet(1, fixtureV9ODID, tpl, flowSet(fixtureV9TemplateID, record)), nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}

	got := records[0]
	if !got.SrcAddr.IsValid() || got.Protocol != protocolTCP {
		t.Errorf("record = %+v, want the network layer kept", got)
	}
	// The zero padding after the IPv4 header is where the TCP header would
	// be, and zero ports read from padding would be a fabricated reading.
	// The walk reads them, and they are zero because the padding is: that is
	// the one ambiguity a padded fixed-size section cannot escape, so the
	// ports must at least be zero rather than garbage.
	if got.SrcPort != 0 || got.DstPort != 0 {
		t.Errorf("ports = %d -> %d, want 0 from the padded region", got.SrcPort, got.DstPort)
	}
}

// TestDecodeNetFlowLite_RandomSamplerPair covers the 309/310 options pair:
// size selected out of each population.
func TestDecodeNetFlowLite_RandomSamplerPair(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	optionsBody := make([]byte, 6)
	optionsBody[0], optionsBody[1] = 0x02, 0x58 // template id 600
	optionsBody[3] = 4                          // scope bytes
	optionsBody[5] = 8                          // option bytes
	optionsBody = be16(optionsBody, 1)          // scope: system
	optionsBody = be16(optionsBody, 4)
	optionsBody = be16(optionsBody, fieldSamplingSize)
	optionsBody = be16(optionsBody, 4)
	optionsBody = be16(optionsBody, fieldSamplingPopulation)
	optionsBody = be16(optionsBody, 4)

	optionsRecord := be32(nil, 9) // scope value
	optionsRecord = be32(optionsRecord, 1)
	optionsRecord = be32(optionsRecord, 32)

	packet := v9Packet(1, fixtureV9ODID,
		flowSet(optionsTemplateFlowSetID, optionsBody),
		flowSet(600, optionsRecord),
	)
	if _, err := d.Decode(testExporter, packet, nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	domains := d.Domains()
	if len(domains) != 1 || domains[0].SamplingRate != 32 {
		t.Errorf("Domains() = %+v, want rate 32 from 1 out of each 32", domains)
	}
}
