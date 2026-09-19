package decoder

import (
	"net/netip"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// FuzzDecode asserts that no datagram, however broken, panics the decoder or
// yields records alongside an error. Every datagram is untrusted input.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x05})
	f.Add(buildV5Packet(1))
	f.Add(buildV5Packet(netflowV5MaxCount))
	f.Add([]byte{0x00, 0x00, 0x00, 0x05})
	f.Add([]byte{0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00})
	f.Add(append(buildV8Header(1, 1), make([]byte, 28)...))
	f.Add(append(buildV8Header(8, 1), make([]byte, 44)...))
	f.Add(append(buildV8Header(14, 2), make([]byte, 80)...))
	f.Add(v9Packet(1, fixtureV9ODID, fixtureV9Template()))
	f.Add(v9Packet(2, fixtureV9ODID, fixtureV9Template(), flowSet(fixtureV9TemplateID, fixtureV9DataRecord())))
	f.Add(v9Packet(3, fixtureV9ODID, flowSet(2, []byte{0, 0, 0, 0})))
	f.Add(ipfixMessage(0, fixtureIPFIXTemplate()))
	f.Add(ipfixMessage(1, fixtureIPFIXTemplate(),
		flowSet(fixtureIPFIXTemplateID, fixtureIPFIXRecord())))
	f.Add(ipfixMessage(2,
		ipfixTemplateSet(ipfixSpec(fieldApplicationName, variableFieldLength, 0)),
		flowSet(fixtureIPFIXTemplateID, []byte{255, 0, 3, 'a', 'b', 'c'})))
	f.Add(sflowDatagram(1, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(1000, 3, 4, rawHeaderRecord(tcpFrame(false), 1518)))))
	f.Add(v9Packet(4, fixtureV9ODID,
		flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
			[2]uint16{fieldPacketSectionV9Data, fixtureSectionSize})),
		flowSet(fixtureV9TemplateID, padTo(tcpFrame(false)))))
	f.Add(ipfixMessage(3,
		ipfixTemplateSet(
			ipfixSpec(fieldDataLinkFrameSize, 4, 0),
			ipfixSpec(fieldDataLinkFrameSection, variableFieldLength, 0)),
		flowSet(fixtureIPFIXTemplateID, append(append(be32(nil, 1518),
			byte(len(tcpFrame(true)))), tcpFrame(true)...))))
	f.Add(sflowDatagram(2, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(10, 1, 2, rawHeaderRecord(tcpFrame(true), 900)))))

	// The expanded sample and the withdrawal are the two shapes whose head
	// differs from the form beside them, so a walk that takes the wrong
	// length desynchronizes the rest of the datagram rather than failing.
	f.Add(sflowDatagram(3, sflowSampleWithInterfaces(true,
		[]uint32{0, 3}, []uint32{0, 4}, rawHeaderRecord(tcpFrame(false), 1518))))
	f.Add(sflowDatagram(4, sflowSample(sflowFlowSample,
		sflowFlowSampleBody(100, 1, 2,
			rawHeaderRecord(tcpFrame(false), 1518),
			sflowRecord(sflowSampledIPv4, make([]byte, 32))))))
	f.Add(ipfixMessage(4, ipfixWithdrawal(ipfixTemplateSetID, fixtureIPFIXTemplateID)))
	f.Add(ipfixMessage(5, ipfixWithdrawal(ipfixOptionsTemplateSetID, ipfixOptionsTemplateSetID)))
	f.Add(ipfixMessage(6, flowSet(ipfixOptionsTemplateSetID,
		append(be16(be16(nil, 700), 0), be16(be16(be16(nil, 701), 2), 1)...))))
	f.Add(ipfixMessage(7, fixtureIPFIXTemplate(),
		flowSet(fixtureIPFIXTemplateID, nil)))

	// The clock shapes, whose arithmetic is modular: a pair behind the wrap,
	// a pair that inverts, one element of a pair, and the IPFIX record that
	// carries its own anchor.
	f.Add(v9ClockPacket(100_000, beforeWrap(10_000), beforeWrap(5_000)))
	f.Add(v9ClockPacket(120_000, 45_000, 30_000))
	f.Add(v9Packet(5, fixtureV9ODID,
		flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
			[2]uint16{fieldFirstSwitched, 4})),
		flowSet(fixtureV9TemplateID, be32(nil, 30_000))))
	f.Add(ipfixMessage(8,
		ipfixTemplateSet(
			ipfixSpec(fieldSystemInitTime, 8, 0),
			ipfixSpec(fieldFirstSwitched, 4, 0),
			ipfixSpec(fieldLastSwitched, 4, 0)),
		flowSet(fixtureIPFIXTemplateID,
			be32(be32(be64(nil, uint64(fixtureIPFIXExportSecs)*1000-3_600_000), 3_540_000), 3_570_000))))

	exporter := netip.MustParseAddr("192.0.2.99")

	f.Fuzz(func(t *testing.T, payload []byte) {
		d := New(config.Parser{
			MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          config.DefaultParserTemplateTTL,
		})

		records, err := d.Decode(sentFrom(exporter), payload, nil)
		if err != nil && len(records) != 0 {
			t.Errorf("Decode() returned %d records alongside error %v, want 0", len(records), err)
		}
	})
}

// FuzzDecodeSequence drives one decoder with two datagrams in order. The
// template-driven protocols carry state between datagrams, and the version is
// a property of the datagram rather than of the domain, so a template
// announced under one version and named under the other is reachable only
// across a sequence. FuzzDecode builds a fresh decoder per input and cannot
// express that.
func FuzzDecodeSequence(f *testing.F) {
	exporter := netip.MustParseAddr("192.0.2.10")

	f.Add(ipfixMessage(0, ipfixTemplateSet(ipfixSpec(fieldApplicationName, variableFieldLength, 0))),
		v9Packet(1, fixtureIPFIXODID, flowSet(fixtureIPFIXTemplateID, []byte{0, 0, 0, 0})))
	f.Add(v9Packet(1, fixtureIPFIXODID, fixtureV9Template()),
		ipfixMessage(0, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())))
	f.Add(ipfixMessage(0, fixtureIPFIXTemplate()),
		ipfixMessage(1, flowSet(fixtureIPFIXTemplateID, fixtureIPFIXRecord())))
	f.Add(v9Packet(1, fixtureV9ODID, fixtureV9Template()),
		v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())))
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, first, second []byte) {
		d := New(config.Parser{
			MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          config.DefaultParserTemplateTTL,
		})

		for _, payload := range [][]byte{first, second} {
			records, err := d.Decode(sentFrom(exporter), payload, nil)
			if err != nil && len(records) != 0 {
				t.Errorf("Decode() returned %d records alongside error %v, want 0", len(records), err)
			}
		}
	})
}
