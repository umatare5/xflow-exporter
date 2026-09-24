package decoder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	fixtureIPFIXExportSecs = 1_756_400_000
	fixtureIPFIXODID       = 512
	fixtureIPFIXTemplateID = 400
)

// ipfixMessage assembles one IPFIX message with a correct length field.
func ipfixMessage(sequence uint32, sets ...[]byte) []byte {
	payload := make([]byte, ipfixHeaderLen)
	binary.BigEndian.PutUint16(payload[0:2], 10)
	binary.BigEndian.PutUint32(payload[4:8], fixtureIPFIXExportSecs)
	binary.BigEndian.PutUint32(payload[8:12], sequence)
	binary.BigEndian.PutUint32(payload[12:16], fixtureIPFIXODID)
	for _, set := range sets {
		payload = append(payload, set...)
	}
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
	return payload
}

// ipfixSpec writes one field specifier, with the enterprise form when pen is
// non-zero.
func ipfixSpec(fieldType, length uint16, pen uint32) []byte {
	spec := make([]byte, 4)
	if pen != 0 {
		binary.BigEndian.PutUint16(spec[0:2], fieldType|enterpriseBit)
	} else {
		binary.BigEndian.PutUint16(spec[0:2], fieldType)
	}
	binary.BigEndian.PutUint16(spec[2:4], length)
	if pen != 0 {
		var e [4]byte
		binary.BigEndian.PutUint32(e[:], pen)
		spec = append(spec, e[:]...)
	}
	return spec
}

// ipfixTemplateSet announces one template under the fixture id.
func ipfixTemplateSet(specs ...[]byte) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], fixtureIPFIXTemplateID)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(specs)))
	for _, spec := range specs {
		body = append(body, spec...)
	}
	return flowSet(ipfixTemplateSetID, body)
}

// fixtureIPFIXTemplate announces an IPv6 template with an enterprise field
// this exporter skips.
func fixtureIPFIXTemplate() []byte {
	return ipfixTemplateSet(
		ipfixSpec(fieldIPv6SrcAddr, 16, 0),
		ipfixSpec(fieldIPv6DstAddr, 16, 0),
		ipfixSpec(fieldL4SrcPort, 2, 0),
		ipfixSpec(fieldL4DstPort, 2, 0),
		ipfixSpec(fieldProtocol, 1, 0),
		ipfixSpec(9999, 4, 12325), // vendor field, skipped by length
		ipfixSpec(fieldInBytes, 8, 0),
		ipfixSpec(fieldInPackets, 8, 0),
		ipfixSpec(fieldFlowStartMilliseconds, 8, 0),
		ipfixSpec(fieldFlowEndMilliseconds, 8, 0),
	)
}

// fixtureIPFIXRecord matches fixtureIPFIXTemplate.
func fixtureIPFIXRecord() []byte {
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")

	record := make([]byte, 0, 77)
	record = append(record, src.AsSlice()...)
	record = append(record, dst.AsSlice()...)
	record = be16(record, 51234)
	record = be16(record, 443)
	record = append(record, 6)
	record = be32(record, 0xDEADBEEF) // vendor field payload
	record = be64(record, 512000)
	record = be64(record, 1000)
	record = be64(record, 1_756_400_100_000)
	record = be64(record, 1_756_400_160_000)
	return record
}

func be64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

// TestDecodeIPFIX_IPv4MappedAddressBecomesIPv4 covers the device that carries
// its IPv4 flows in the IPv6 fields. The two spellings are distinct netip
// values, so a record left mapped would miss a threat list holding the IPv4
// form and would key the aggregation separately from the same host's other
// flows.
func TestDecodeIPFIX_IPv4MappedAddressBecomesIPv4(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	record := fixtureIPFIXRecord()
	copy(record[0:16], netip.MustParseAddr("::ffff:198.51.100.7").AsSlice())
	copy(record[16:32], netip.MustParseAddr("::ffff:203.0.113.9").AsSlice())

	message := ipfixMessage(0, fixtureIPFIXTemplate(),
		flowSet(fixtureIPFIXTemplateID, record),
	)

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}

	got := records[0]
	if got.SrcAddr != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("SrcAddr = %v, want the unmapped 198.51.100.7", got.SrcAddr)
	}
	if got.DstAddr != netip.MustParseAddr("203.0.113.9") {
		t.Errorf("DstAddr = %v, want the unmapped 203.0.113.9", got.DstAddr)
	}
}

// addressOrders returns every ordering of the four address elements, so a
// template's declaration order is exercised exhaustively rather than sampled.
func addressOrders() [][]int {
	orders := [][]int{{0}}
	for n := 2; n <= 4; n++ {
		var next [][]int
		for _, sub := range orders {
			for pos := 0; pos <= len(sub); pos++ {
				o := make([]int, 0, n)
				o = append(o, sub[:pos]...)
				o = append(o, n-1)
				o = append(o, sub[pos:]...)
				next = append(next, o)
			}
		}
		orders = next
	}
	return orders
}

// TestDecodeIPFIX_DualFamilyResolvesTheSameInAnyTemplateOrder covers the
// template that announces both address families in one record and zero-fills
// the pair that does not apply. The zero value of either family is a valid
// address rather than an absent one, so no element can be judged as it
// arrives: every ordering has to reach the family the device measured.
func TestDecodeIPFIX_DualFamilyResolvesTheSameInAnyTemplateOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		v4Src, v4Dst     string
		v6Src, v6Dst     string
		wantSrc, wantDst string
	}{
		{
			name:  "the IPv6 pair carries the flow",
			v4Src: "0.0.0.0", v4Dst: "0.0.0.0",
			v6Src: "2001:db8::1", v6Dst: "2001:db8::2",
			wantSrc: "2001:db8::1", wantDst: "2001:db8::2",
		},
		{
			name:  "the IPv4 pair carries the flow",
			v4Src: "198.51.100.7", v4Dst: "203.0.113.9",
			v6Src: "::", v6Dst: "::",
			wantSrc: "198.51.100.7", wantDst: "203.0.113.9",
		},
		{
			name:  "an IPv4 DHCP client with no lease yet",
			v4Src: "0.0.0.0", v4Dst: "255.255.255.255",
			v6Src: "::", v6Dst: "::",
			wantSrc: "0.0.0.0", wantDst: "255.255.255.255",
		},
		{
			name:  "an IPv6 host joining a multicast group before it is addressed",
			v4Src: "0.0.0.0", v4Dst: "0.0.0.0",
			v6Src: "::", v6Dst: "ff02::1",
			wantSrc: "::", wantDst: "ff02::1",
		},
		{
			// The rule reads both sides of a pair, so a family holding a
			// reading on the source alone carries the flow just as one
			// holding it on the destination does.
			name:  "only the source of a pair carries a reading",
			v4Src: "0.0.0.0", v4Dst: "0.0.0.0",
			v6Src: "2001:db8::1", v6Dst: "::",
			wantSrc: "2001:db8::1", wantDst: "::",
		},
		{
			// One flow with two sources is a contradiction no device can
			// have measured, so there is no right answer -- only a settled
			// one, without which the same flow keys two series.
			name:  "both families carry a reading",
			v4Src: "198.51.100.7", v4Dst: "203.0.113.9",
			v6Src: "2001:db8::1", v6Dst: "2001:db8::2",
			wantSrc: "198.51.100.7", wantDst: "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			elements := []struct {
				field uint16
				width uint16
				value string
			}{
				{fieldIPv4SrcAddr, ipv4Len, tt.v4Src},
				{fieldIPv4DstAddr, ipv4Len, tt.v4Dst},
				{fieldIPv6SrcAddr, ipv6Len, tt.v6Src},
				{fieldIPv6DstAddr, ipv6Len, tt.v6Dst},
			}

			for _, order := range addressOrders() {
				specs := make([][]byte, 0, 6)
				record := make([]byte, 0, 49)
				declared := ""
				for _, i := range order {
					specs = append(specs, ipfixSpec(elements[i].field, elements[i].width, 0))
					record = append(record, netip.MustParseAddr(elements[i].value).AsSlice()...)
					declared += " " + elements[i].value
				}
				specs = append(specs, ipfixSpec(fieldProtocol, 1, 0), ipfixSpec(fieldInBytes, 8, 0))
				record = append(record, protocolTCP)
				record = be64(record, 4096)

				d := newTestDecoder()
				message := ipfixMessage(0, ipfixTemplateSet(specs...), flowSet(fixtureIPFIXTemplateID, record))

				records, err := d.Decode(sentFrom(testExporter), message, nil)
				if err != nil || len(records) != 1 {
					t.Fatalf("order%s: Decode() = %d records, %v; want 1, nil", declared, len(records), err)
				}

				got := records[0]
				if got.SrcAddr != netip.MustParseAddr(tt.wantSrc) || got.DstAddr != netip.MustParseAddr(tt.wantDst) {
					t.Errorf("order%s: got %v -> %v, want %s -> %s",
						declared, got.SrcAddr, got.DstAddr, tt.wantSrc, tt.wantDst)
				}
			}
		})
	}
}

// TestDecodeIPFIX_UnspecifiedAddressIsStillRecorded pins the other half of the
// rule: a single-family template carries no filler to tell apart from a
// reading, so the unspecified address a device really saw is published.
func TestDecodeIPFIX_UnspecifiedAddressIsStillRecorded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		srcField         uint16
		dstField         uint16
		width            uint16
		src, dst         string
		wantSrc, wantDst string
	}{
		{
			name:     "a DHCP client with no lease yet",
			srcField: fieldIPv4SrcAddr, dstField: fieldIPv4DstAddr, width: ipv4Len,
			src: "0.0.0.0", dst: "255.255.255.255",
			wantSrc: "0.0.0.0", wantDst: "255.255.255.255",
		},
		{
			name:     "neither side addressed",
			srcField: fieldIPv4SrcAddr, dstField: fieldIPv4DstAddr, width: ipv4Len,
			src: "0.0.0.0", dst: "0.0.0.0",
			wantSrc: "0.0.0.0", wantDst: "0.0.0.0",
		},
		{
			name:     "neither side addressed, over IPv6",
			srcField: fieldIPv6SrcAddr, dstField: fieldIPv6DstAddr, width: ipv6Len,
			src: "::", dst: "::",
			wantSrc: "::", wantDst: "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			singleFamily := ipfixTemplateSet(
				ipfixSpec(tt.srcField, tt.width, 0),
				ipfixSpec(tt.dstField, tt.width, 0),
				ipfixSpec(fieldProtocol, 1, 0),
				ipfixSpec(fieldInBytes, 8, 0),
			)

			record := make([]byte, 0, 41)
			record = append(record, netip.MustParseAddr(tt.src).AsSlice()...)
			record = append(record, netip.MustParseAddr(tt.dst).AsSlice()...)
			record = append(record, protocolUDP)
			record = be64(record, 328)

			d := newTestDecoder()
			message := ipfixMessage(0, singleFamily, flowSet(fixtureIPFIXTemplateID, record))

			records, err := d.Decode(sentFrom(testExporter), message, nil)
			if err != nil || len(records) != 1 {
				t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
			}

			got := records[0]
			if got.SrcAddr != netip.MustParseAddr(tt.wantSrc) || got.DstAddr != netip.MustParseAddr(tt.wantDst) {
				t.Errorf("got %v -> %v, want the reading the device sent, %s -> %s",
					got.SrcAddr, got.DstAddr, tt.wantSrc, tt.wantDst)
			}
		})
	}
}

// TestDecodeIPFIX_TemplatePairingOneFamilyPerSideKeepsBoth pins the template
// that declares one family's source element and the other's destination. The
// pair that carries a reading is taken whole, and the other fills only the
// side it left absent, so neither address the device sent is discarded.
func TestDecodeIPFIX_TemplatePairingOneFamilyPerSideKeepsBoth(t *testing.T) {
	t.Parallel()

	mixed := ipfixTemplateSet(
		ipfixSpec(fieldIPv4SrcAddr, ipv4Len, 0),
		ipfixSpec(fieldIPv6DstAddr, ipv6Len, 0),
		ipfixSpec(fieldInBytes, 8, 0),
	)

	record := make([]byte, 0, 28)
	record = append(record, netip.MustParseAddr("198.51.100.7").AsSlice()...)
	record = append(record, netip.MustParseAddr("2001:db8::9").AsSlice()...)
	record = be64(record, 64)

	d := newTestDecoder()
	message := ipfixMessage(0, mixed, flowSet(fixtureIPFIXTemplateID, record))

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}

	got := records[0]
	if got.SrcAddr != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("SrcAddr = %v, want 198.51.100.7", got.SrcAddr)
	}
	if got.DstAddr != netip.MustParseAddr("2001:db8::9") {
		t.Errorf("DstAddr = %v, want 2001:db8::9", got.DstAddr)
	}
}

func TestDecodeIPFIX_TemplateThenData(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	message := ipfixMessage(0, fixtureIPFIXTemplate(),
		flowSet(fixtureIPFIXTemplateID, fixtureIPFIXRecord()),
	)

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}

	want := flow.Record{
		Exporter:        testExporter,
		Version:         flow.VersionIPFIX,
		ODID:            fixtureIPFIXODID,
		SrcAddr:         netip.MustParseAddr("2001:db8::1"),
		DstAddr:         netip.MustParseAddr("2001:db8::2"),
		SrcPort:         51234,
		DstPort:         443,
		Protocol:        6,
		Bytes:           512000,
		Packets:         1000,
		BytesReported:   true,
		PacketsReported: true,
		Flows:           1,
		Start:           time.UnixMilli(1_756_400_100_000),
		End:             time.UnixMilli(1_756_400_160_000),
	}
	if records[0] != want {
		t.Errorf("Decode() record =\n%+v\nwant\n%+v", records[0], want)
	}
}

func TestDecodeIPFIX_VariableLengthFields(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := ipfixTemplateSet(
		ipfixSpec(fieldInBytes, 4, 0),
		ipfixSpec(fieldApplicationName, variableFieldLength, 0),
		ipfixSpec(fieldInPackets, 4, 0),
	)

	// Two records: a short-form and a long-form variable value, so the walk
	// must resynchronize correctly after each.
	shortForm := be32(nil, 100)
	shortForm = append(shortForm, 3)
	shortForm = append(shortForm, []byte("ssh")...)
	shortForm = be32(shortForm, 7)

	longValue := make([]byte, 300)
	copy(longValue, "web-browsing")
	longForm := be32(nil, 200)
	longForm = append(longForm, 255)
	longForm = be16(longForm, 300)
	longForm = append(longForm, longValue...)
	longForm = be32(longForm, 9)

	message := ipfixMessage(0, tpl,
		flowSet(fixtureIPFIXTemplateID, shortForm, longForm))

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 2 {
		t.Fatalf("Decode() returned %d records, want 2", len(records))
	}
	if records[0].Bytes != 100 || records[0].AppName != "ssh" || records[0].Packets != 7 {
		t.Errorf("short-form record = %+v, want bytes 100, app ssh, packets 7", records[0])
	}
	if records[1].Bytes != 200 || records[1].AppName != "web-browsing" || records[1].Packets != 9 {
		t.Errorf("long-form record = %+v, want bytes 200, app web-browsing, packets 9", records[1])
	}
}

// messageEndingIn is one IPFIX message opening on sets that each take
// effect, a sampling declaration and two templates, and ending in tail.
func messageEndingIn(tail ...[]byte) []byte {
	optionsTemplate := ipfixOptionsTemplate(300, ipfixSpec(144, 4, 0), ipfixSpec(fieldSamplingInterval, 4, 0))
	declaration := flowSet(300, be32(be32(nil, 1), 100))
	dataTemplate := ipfixTemplateSet(
		ipfixSpec(fieldInBytes, 4, 0), ipfixSpec(fieldApplicationName, variableFieldLength, 0))
	return ipfixMessage(0, append([][]byte{optionsTemplate, declaration, dataTemplate}, tail...)...)
}

// TestDecodeIPFIX_DiscardsAMalformedMessageWhole pins RFC 7011 section 9.1: a
// length that does not fit what encloses it discards the message whole, so
// no record, template or declaration in it takes effect, those ahead of the
// fault included.
func TestDecodeIPFIX_DiscardsAMalformedMessageWhole(t *testing.T) {
	t.Parallel()

	record := append(be32(nil, 10), 3, 'a', 'b', 'c')
	tests := []struct {
		name      string
		message   []byte
		malformed bool
	}{
		{name: "well formed", message: messageEndingIn(flowSet(fixtureIPFIXTemplateID, record))},
		{
			name:      "variable-length value past its set",
			message:   messageEndingIn(flowSet(fixtureIPFIXTemplateID, record, append(be32(nil, 20), 200, 'x'))),
			malformed: true,
		},
		{
			name:      "data set shorter than a record",
			message:   messageEndingIn(flowSet(fixtureIPFIXTemplateID, record[:3])),
			malformed: true,
		},
		{
			name:      "set running past the message",
			message:   messageEndingIn(flowSet(fixtureIPFIXTemplateID, record), be16(be16(nil, 400), 60000)),
			malformed: true,
		},
		{
			name:      "set shorter than its header",
			message:   messageEndingIn(flowSet(fixtureIPFIXTemplateID, record), be16(be16(nil, 400), 2)),
			malformed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			records, err := d.Decode(sentFrom(testExporter), tt.message, nil)
			domain := oneDomain(t, d)
			if !tt.malformed {
				if err != nil || len(records) != 1 || domain.Templates != 1 || domain.OptionsTemplates != 1 ||
					domain.SamplingRate != 100 {
					t.Fatalf("Decode() = %d records, %v, domain %+v, want every set in effect",
						len(records), err, domain)
				}
				return
			}

			var de *decodeError
			if !errors.As(err, &de) || de.Reason() != ReasonMalformed {
				t.Fatalf("Decode() error = %v, want a malformed rejection", err)
			}
			if len(records) != 0 || domain.Templates != 0 || domain.OptionsTemplates != 0 || domain.SamplingRate != 0 {
				t.Errorf("Decode() = %d records, domain %+v, want nothing from the message in effect",
					len(records), domain)
			}
			if got := errorCountFor(d, flow.VersionIPFIX, ReasonMalformed); got != 1 {
				t.Errorf("malformed count = %d, want 1", got)
			}
		})
	}
}

// TestDecodeIPFIX_DiscardsAgainstAStoredTemplate pins the check to the
// template an earlier message stored, which a data-only message names.
func TestDecodeIPFIX_DiscardsAgainstAStoredTemplate(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	announce := ipfixMessage(0, ipfixTemplateSet(ipfixSpec(fieldApplicationName, variableFieldLength, 0)))
	if _, err := d.Decode(sentFrom(testExporter), announce, nil); err != nil {
		t.Fatalf("Decode() error = %v announcing the template", err)
	}

	message := ipfixMessage(1, flowSet(fixtureIPFIXTemplateID, []byte{3, 'a', 'b', 'c'}, []byte{200, 'x'}))
	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err == nil || len(records) != 0 {
		t.Errorf("Decode() = %d records, %v, want the message discarded", len(records), err)
	}
}

// TestDecodeIPFIX_RefusedTemplateJudgesNoData pins the check to the templates
// registration would store: one whose record cannot fit a set is refused, so
// the data set naming it is missing its template rather than malformed.
func TestDecodeIPFIX_RefusedTemplateJudgesNoData(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	message := ipfixMessage(0,
		ipfixTemplateSet(ipfixSpec(fieldInBytes, 40000, 0), ipfixSpec(fieldInPackets, 40000, 0)),
		flowSet(fixtureIPFIXTemplateID, be32(nil, 1)))
	if _, err := d.Decode(sentFrom(testExporter), message, nil); err != nil {
		t.Fatalf("Decode() error = %v, want the message read", err)
	}
	for _, reason := range []string{ReasonInvalidTemplate, ReasonMissingTemplate} {
		if got := errorCountFor(d, flow.VersionIPFIX, reason); got != 1 {
			t.Errorf("%s count = %d, want 1", reason, got)
		}
	}
}

// TestDecodeIPFIX_DiscardWithdrawsARedefinedLayout pins what a discarded
// message leaves of the IDs it announces: one it redefines, ahead of the fault
// or behind a data set that fails, is withdrawn, and one it refreshes keeps
// its layout.
func TestDecodeIPFIX_DiscardWithdrawsARedefinedLayout(t *testing.T) {
	t.Parallel()

	held := ipfixTemplateSet(ipfixSpec(fieldIPv4SrcAddr, 4, 0), ipfixSpec(fieldInBytes, 4, 0))
	redefined := ipfixTemplateSet(
		ipfixSpec(fieldIPv4SrcAddr, 4, 0), ipfixSpec(fieldIPv4DstAddr, 4, 0), ipfixSpec(fieldInBytes, 4, 0))
	refused := ipfixTemplateSet(ipfixSpec(fieldIPv4SrcAddr, 4, 0), ipfixSpec(fieldIPv4DstAddr, 0, 0))
	short := flowSet(fixtureIPFIXTemplateID, []byte{10, 0, 0, 1, 0})
	// Two records of the redefined layout, which the held one reads as three.
	next := flowSet(fixtureIPFIXTemplateID, be32(be32(be32(be32(be32(be32(nil,
		0x0a000001), 0x0a000002), 1000), 0x0a000003), 0x0a000004), 2000))

	tests := []struct {
		name      string
		sets      [][]byte
		withdrawn bool
	}{
		{"redefined ahead of a short data set", [][]byte{redefined, short}, true},
		{"redefined behind a short data set", [][]byte{short, redefined}, true},
		{"redefined ahead of a set shorter than its header", [][]byte{redefined, be16(be16(nil, 500), 2)}, true},
		{"redefined ahead of a set running past the message", [][]byte{redefined, be16(be16(nil, 500), 60000)}, true},
		{"refused behind a short data set", [][]byte{short, refused}, true},
		{"redefined behind another ID's refusal", [][]byte{short, flowSet(ipfixTemplateSetID,
			be16(be16(nil, 500), 1), ipfixSpec(fieldInBytes, 0, 0), redefined[flowSetHeaderLen:])}, true},
		{"refreshed ahead of a short data set", [][]byte{held, short}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decode := func(sequence uint32, sets ...[]byte) ([]flow.Record, error) {
				return d.Decode(sentFrom(testExporter), ipfixMessage(sequence, sets...), nil)
			}
			if _, err := decode(0, held); err != nil {
				t.Fatalf("Decode() error = %v announcing the held layout", err)
			}
			if _, err := decode(1, tt.sets...); err == nil {
				t.Fatal("Decode() error = nil, want the message discarded")
			}

			if !tt.withdrawn {
				if got := oneDomain(t, d).Templates; got != 1 {
					t.Errorf("templates = %d, want the refreshed layout kept", got)
				}
				return
			}
			records, _ := decode(2, next)
			if len(records) != 0 {
				t.Errorf("Decode() = %d records, want none from the layout the device left", len(records))
			}
			if got := errorCountFor(d, flow.VersionIPFIX, ReasonMissingTemplate); got != 1 {
				t.Errorf("missing_template count = %d, want 1", got)
			}
		})
	}
}

// TestDecodeIPFIX_ReadsPastARefusedTemplate pins that a refused template
// leaves the announcements behind it in its set readable, its specifiers
// stepped over with their enterprise numbers, so an ID redefined there takes
// the layout the device sent.
func TestDecodeIPFIX_ReadsPastARefusedTemplate(t *testing.T) {
	t.Parallel()

	templateRecord := func(id uint16, specs ...[]byte) []byte {
		body := be16(be16(nil, id), uint16(len(specs)))
		for _, spec := range specs {
			body = append(body, spec...)
		}
		return body
	}
	optionsRecord := func(id, scopeCount uint16, specs ...[]byte) []byte {
		body := be16(be16(be16(nil, id), uint16(len(specs))), scopeCount)
		for _, spec := range specs {
			body = append(body, spec...)
		}
		return body
	}
	overLimit := make([][]byte, config.DefaultParserMaxFieldsPerTemplate+1)
	for i := range overLimit {
		overLimit[i] = ipfixSpec(9999, 4, 12325)
	}
	redefined := templateRecord(fixtureIPFIXTemplateID,
		ipfixSpec(fieldIPv4SrcAddr, 4, 0), ipfixSpec(fieldIPv4DstAddr, 4, 0), ipfixSpec(fieldInBytes, 4, 0))
	redefinedAsOptions := optionsRecord(fixtureIPFIXTemplateID, 1, ipfixSpec(1, 4, 0), ipfixSpec(fieldInBytes, 8, 0))

	tests := []struct {
		name    string
		set     []byte
		records int
	}{
		{
			name: "zero-width field",
			set: flowSet(ipfixTemplateSetID,
				templateRecord(500, ipfixSpec(9999, 4, 12325), ipfixSpec(fieldInBytes, 0, 0)), redefined),
			records: 2,
		},
		{
			name:    "template id in the reserved range",
			set:     flowSet(ipfixTemplateSetID, templateRecord(255, ipfixSpec(fieldInBytes, 4, 0)), redefined),
			records: 2,
		},
		{
			name:    "field count past the limit",
			set:     flowSet(ipfixTemplateSetID, templateRecord(500, overLimit...), redefined),
			records: 2,
		},
		{
			name: "no scope field",
			set: flowSet(ipfixOptionsTemplateSetID,
				optionsRecord(500, 0, ipfixSpec(1, 4, 0), ipfixSpec(fieldInBytes, 4, 0)), redefinedAsOptions),
		},
		{
			name: "zero-width option field",
			set: flowSet(ipfixOptionsTemplateSetID,
				optionsRecord(500, 1, ipfixSpec(1, 4, 0), ipfixSpec(fieldInBytes, 0, 0)), redefinedAsOptions),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decode := func(sequence uint32, set []byte) []flow.Record {
				records, err := d.Decode(sentFrom(testExporter), ipfixMessage(sequence, set), nil)
				if err != nil {
					t.Fatalf("Decode() error = %v, want the message read", err)
				}
				return records
			}
			decode(0, ipfixTemplateSet(ipfixSpec(fieldIPv4SrcAddr, 4, 0), ipfixSpec(fieldInBytes, 4, 0)))
			decode(1, tt.set)

			// Two records of the redefined layout, which the held one reads as three.
			records := decode(2, flowSet(fixtureIPFIXTemplateID, be32(be32(be32(be32(be32(be32(nil,
				0x0a000001), 0x0a000002), 1000), 0x0a000003), 0x0a000004), 2000)))
			if len(records) != tt.records {
				t.Errorf("Decode() = %d records, want %d from the layout the device sent", len(records), tt.records)
			}
			if got := errorCountFor(d, flow.VersionIPFIX, ReasonInvalidTemplate); got != 1 {
				t.Errorf("invalid_template count = %d, want 1", got)
			}
			if got := errorCountFor(d, flow.VersionIPFIX, ReasonMissingTemplate); got != 0 {
				t.Errorf("missing_template count = %d, want the redefinition held", got)
			}
		})
	}
}

// errorCountFor reads one error counter for a version.
func errorCountFor(d *Decoder, version flow.Version, reason string) uint64 {
	for _, snap := range d.Stats().Snapshot() {
		for _, e := range snap.Errors {
			if e.Version == version && e.Reason == reason {
				return e.Count
			}
		}
	}
	return 0
}

// ipfixOptionsTemplate announces one options template whose first spec is its
// only scope field, the shape RFC 6759 gives both AVC tables.
func ipfixOptionsTemplate(id uint16, specs ...[]byte) []byte {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(specs)))
	binary.BigEndian.PutUint16(body[4:6], 1)
	for _, spec := range specs {
		body = append(body, spec...)
	}
	return flowSet(ipfixOptionsTemplateSetID, body)
}

// TestDecodeIPFIX_NBARApplicationTableResolvesRecords covers the two options
// templates a device exporting AVC announces, in the shape RFC 6759 defines
// them: sections 6.8 and 6.9 both put applicationId in the scope, so the
// field naming what the record describes is the one in the scope area.
func TestDecodeIPFIX_NBARApplicationTableResolvesRecords(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	appID := uint32(0x0D_00_00_2A) // engine 13, selector 42

	// RFC 6759 6.8, the application name mapping.
	nameTemplate := ipfixOptionsTemplate(600,
		ipfixSpec(fieldApplicationID, 4, 0),
		ipfixSpec(fieldApplicationName, variableFieldLength, 0),
	)
	nameRecord := be32(nil, appID)
	nameRecord = append(nameRecord, 5)
	nameRecord = append(nameRecord, []byte("https")...)

	// RFC 6759 6.9, the attribute values.
	attributeTemplate := ipfixOptionsTemplate(601,
		ipfixSpec(fieldApplicationID, 4, 0),
		ipfixSpec(fieldCiscoAppCategory, variableFieldLength, ciscoPEN),
	)
	attributeRecord := be32(nil, appID)
	attributeRecord = append(attributeRecord, 8)
	attributeRecord = append(attributeRecord, []byte("browsing")...)

	dataTemplate := ipfixTemplateSet(
		ipfixSpec(fieldInBytes, 4, 0),
		ipfixSpec(fieldApplicationID, 4, 0),
	)
	dataRecord := be32(nil, 999)
	dataRecord = be32(dataRecord, appID)

	message := ipfixMessage(0,
		nameTemplate, flowSet(600, nameRecord),
		attributeTemplate, flowSet(601, attributeRecord),
		dataTemplate, flowSet(fixtureIPFIXTemplateID, dataRecord),
	)

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1 flow record", len(records))
	}

	got := records[0]
	if got.AppID != appID {
		t.Errorf("AppID = %#x, want %#x", got.AppID, appID)
	}
	if got.AppName != "https" {
		t.Errorf("AppName = %q, want https resolved from the application table", got.AppName)
	}
	if got.AppCategory != "browsing" {
		t.Errorf("AppCategory = %q, want browsing resolved from the attributes", got.AppCategory)
	}
}

func TestDecodeIPFIX_UnresolvedApplicationStaysNumbered(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	dataTemplate := ipfixTemplateSet(
		ipfixSpec(fieldApplicationID, 4, 0),
	)
	record := be32(nil, 42)

	message := ipfixMessage(0, dataTemplate,
		flowSet(fixtureIPFIXTemplateID, record))

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	if records[0].AppID != 42 || records[0].AppName != "" || records[0].AppCategory != "" {
		t.Errorf("record = %+v, want the identifier kept and the strings absent", records[0])
	}
}

// TestApplicationID_ReadsTheEngineAndTheRightAlignedSelector pins RFC 6759
// section 4.2 on the examples it gives: the engine is the first octet and
// the selector sits in the low bits of the rest at any width. An identifier
// the record cannot carry whole stays unread rather than cut.
func TestApplicationID_ReadsTheEngineAndTheRightAlignedSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value []byte
		want  uint32
		ok    bool
	}{
		{name: "IANA-L3 at two octets", value: []byte{1, 1}, want: 1<<24 | 1, ok: true},
		{name: "IANA-L4 at three octets", value: []byte{3, 0, 161}, want: 3<<24 | 161, ok: true},
		{name: "PANA-L7 at four octets", value: []byte{13, 0, 1, 197}, want: 13<<24 | 453, ok: true},
		{name: "PANA-L7 at eight octets", value: []byte{13, 0, 0, 0, 0, 0, 1, 197}, want: 13<<24 | 453, ok: true},
		{name: "engine 0 as sent", value: []byte{0, 0, 0, 1}, want: 1, ok: true},
		{name: "engine alone", value: []byte{13}},
		{name: "selector past 24 bits", value: []byte{12, 1, 0, 0, 0, 0}},
		{name: "PANA-L7-PEN", value: []byte{20, 0, 0, 0, 9, 0, 39, 16}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, ok := applicationID(tt.value); got != tt.want || ok != tt.ok {
				t.Errorf("applicationID(%v) = %#x, %v, want %#x, %v", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestDecodeIPFIX_ApplicationKeysAlikeAtAnyWidth pins the property the RFC
// 6759 reading exists for: a table widening the identifier and a record
// narrowing it key the same application.
func TestDecodeIPFIX_ApplicationKeysAlikeAtAnyWidth(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	table := ipfixOptionsTemplate(600,
		ipfixSpec(fieldApplicationID, 8, 0),
		ipfixSpec(fieldApplicationName, 3, 0),
	)
	name := []byte{13, 0, 0, 0, 0, 0, 0, 42, 's', 's', 'h'}
	data := ipfixTemplateSet(ipfixSpec(fieldApplicationID, 3, 0))
	message := ipfixMessage(0, table, flowSet(600, name), data,
		flowSet(fixtureIPFIXTemplateID, []byte{13, 0, 42}))

	records, err := d.Decode(sentFrom(testExporter), message, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	if records[0].AppID != 13<<24|42 || records[0].AppName != "ssh" {
		t.Errorf("record = %+v, want 13:42 resolved to ssh", records[0])
	}
}

func TestDecodeIPFIX_PSAMPSamplingPairWins(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	optionsBody := make([]byte, 6)
	binary.BigEndian.PutUint16(optionsBody[0:2], 601)
	binary.BigEndian.PutUint16(optionsBody[2:4], 4)
	binary.BigEndian.PutUint16(optionsBody[4:6], 1)
	optionsBody = append(optionsBody, ipfixSpec(1, 4, 0)...) // scope
	optionsBody = append(optionsBody, ipfixSpec(fieldSamplingPacketInterval, 4, 0)...)
	optionsBody = append(optionsBody, ipfixSpec(fieldSamplingPacketSpace, 4, 0)...)
	optionsBody = append(optionsBody, ipfixSpec(fieldSamplingInterval, 4, 0)...)

	record := be32(nil, 1)      // scope
	record = be32(record, 1)    // interval: 1 selected
	record = be32(record, 999)  // space: 999 skipped
	record = be32(record, 5555) // legacy interval, must lose

	message := ipfixMessage(0, flowSet(ipfixOptionsTemplateSetID, optionsBody),
		flowSet(601, record))

	if _, err := d.Decode(sentFrom(testExporter), message, nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	domains := d.Domains()
	if len(domains) != 1 || domains[0].SamplingRate != 1000 {
		t.Errorf("Domains() = %+v, want sampling rate 1000 from the PSAMP pair", domains)
	}
}

// RFC 7011 section 8.4 tells a collector over UDP to ignore a withdrawal: the
// transport gives no order, so honoring one would drop a template a
// re-announcement had already replaced.
func TestDecodeIPFIX_IgnoresTemplateWithdrawal(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	announce := ipfixMessage(0, fixtureIPFIXTemplate())
	if _, err := d.Decode(sentFrom(testExporter), announce, nil); err != nil {
		t.Fatalf("announce error = %v, want nil", err)
	}
	if got := d.Domains()[0].Templates; got != 1 {
		t.Fatalf("Templates = %d, want 1 after the announcement", got)
	}

	withdrawBody := make([]byte, 4)
	binary.BigEndian.PutUint16(withdrawBody[0:2], fixtureIPFIXTemplateID)
	binary.BigEndian.PutUint16(withdrawBody[2:4], 0)
	withdraw := ipfixMessage(0, flowSet(ipfixTemplateSetID, withdrawBody))
	if _, err := d.Decode(sentFrom(testExporter), withdraw, nil); err != nil {
		t.Fatalf("withdraw error = %v, want nil", err)
	}

	if got := d.Domains()[0].Templates; got != 1 {
		t.Errorf("Templates = %d, want the template kept over UDP", got)
	}
}

func TestDecodeIPFIX_SequenceCountsDataRecords(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := ipfixTemplateSet(ipfixSpec(fieldInBytes, 4, 0))

	// Message 1: seq 100, 2 records. Message 2 arrives claiming seq 105:
	// three records never arrived.
	twoRecords := append(be32(nil, 1), be32(nil, 2)...)
	first := ipfixMessage(100, tpl, flowSet(fixtureIPFIXTemplateID, twoRecords))
	second := ipfixMessage(105, flowSet(fixtureIPFIXTemplateID, be32(nil, 3)))

	if _, err := d.Decode(sentFrom(testExporter), first, nil); err != nil {
		t.Fatalf("first message error = %v, want nil", err)
	}
	if _, err := d.Decode(sentFrom(testExporter), second, nil); err != nil {
		t.Fatalf("second message error = %v, want nil", err)
	}

	if got := d.Domains()[0].SequenceMissed; got != 3 {
		t.Errorf("SequenceMissed = %d, want 3 data records", got)
	}
}

func TestDecodeIPFIX_RejectsBrokenStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "header cut short",
			payload: ipfixMessage(0)[:12],
		},
		{
			name: "message length past the datagram",
			payload: func() []byte {
				p := ipfixMessage(0, fixtureIPFIXTemplate())
				binary.BigEndian.PutUint16(p[2:4], uint16(len(p)+10))
				return p
			}(),
		},
		{
			name: "set running past the message",
			payload: func() []byte {
				p := ipfixMessage(0, fixtureIPFIXTemplate())
				binary.BigEndian.PutUint16(p[ipfixHeaderLen+2:ipfixHeaderLen+4], 60000)
				return p
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			records, err := d.Decode(sentFrom(testExporter), tt.payload, nil)
			if err == nil {
				t.Fatal("Decode() error = nil, want a malformed rejection")
			}
			if len(records) != 0 {
				t.Errorf("Decode() returned %d records alongside the error, want 0", len(records))
			}
		})
	}
}

func BenchmarkDecodeIPFIX(b *testing.B) {
	d := newTestDecoder()
	if _, err := d.Decode(sentFrom(testExporter), ipfixMessage(0, fixtureIPFIXTemplate()), nil); err != nil {
		b.Fatal(err)
	}

	records := make([]byte, 0, 77*15)
	for range 15 {
		records = append(records, fixtureIPFIXRecord()...)
	}
	payload := ipfixMessage(1, flowSet(fixtureIPFIXTemplateID, records))
	dst := make([]flow.Record, 0, 15)

	b.ReportAllocs()
	for b.Loop() {
		var err error
		dst, err = d.Decode(sentFrom(testExporter), payload, dst[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ipfixWithdrawal builds a withdrawal record: the template id and a field
// count of zero, the four octets RFC 7011 figure T defines.
func ipfixWithdrawal(setID uint16, templateIDs ...uint16) []byte {
	body := make([]byte, 0, 4*len(templateIDs))
	for _, id := range templateIDs {
		body = be16(body, id)
		body = be16(body, 0)
	}
	return flowSet(setID, body)
}

// TestDecodeIPFIX_IgnoresOptionsTemplateWithdrawal pins both halves of the
// rule. Section 8.4 keeps the templates, and the reader must still step four
// octets per withdrawal record -- figure T gives it no scope field count -- so
// an announcement sharing the set is read. Stepping six would take the next
// record's id for a scope count and abandon the rest of the set.
func TestDecodeIPFIX_IgnoresOptionsTemplateWithdrawal(t *testing.T) {
	t.Parallel()

	optionsHeld := func(t *testing.T, d *Decoder) int {
		t.Helper()
		domains := d.Domains()
		if len(domains) != 1 {
			t.Fatalf("Domains() returned %d domains, want 1", len(domains))
		}
		return domains[0].OptionsTemplates
	}

	optionsBody := func(id uint16) []byte {
		body := be16(be16(be16(nil, id), 2), 1)
		body = append(body, ipfixSpec(fieldApplicationID, 4, 0)...)
		return append(body, ipfixSpec(fieldApplicationName, 8, 0)...)
	}

	announce := func() []byte {
		return ipfixMessage(0,
			flowSet(ipfixOptionsTemplateSetID, optionsBody(700)),
			flowSet(ipfixOptionsTemplateSetID, optionsBody(701)))
	}

	tests := []struct {
		name string
		set  []byte
		want int
	}{
		{
			name: "one template id",
			set:  ipfixWithdrawal(ipfixOptionsTemplateSetID, 700),
			want: 2,
		},
		{
			name: "several in one set",
			set:  ipfixWithdrawal(ipfixOptionsTemplateSetID, 700, 701),
			want: 2,
		},
		{
			name: "all options templates",
			set:  ipfixWithdrawal(ipfixOptionsTemplateSetID, ipfixOptionsTemplateSetID),
			want: 2,
		},
		{
			// The announcement sits behind the withdrawal in one set, so it
			// is read only when the reader steps the right four octets.
			name: "announcement behind a withdrawal",
			set: flowSet(ipfixOptionsTemplateSetID,
				append(be16(be16(nil, 700), 0), optionsBody(702)...)),
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			if _, err := d.Decode(sentFrom(testExporter), announce(), nil); err != nil {
				t.Fatalf("Decode() error = %v, want the announcement accepted", err)
			}
			if got := optionsHeld(t, d); got != 2 {
				t.Fatalf("options templates held = %d, want 2 before the withdrawal", got)
			}

			if _, err := d.Decode(sentFrom(testExporter), ipfixMessage(1, tt.set), nil); err != nil {
				t.Fatalf("Decode() error = %v, want the set accepted", err)
			}
			if got := optionsHeld(t, d); got != tt.want {
				t.Errorf("options templates held = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestDecodeIPFIX_TCPControlBitsAtTwoOctets covers the element's native
// width. RFC 9565 makes tcpControlBits unsigned16 and puts the control bits
// in its low octet, the one-octet form being reduced-size encoding of the
// same element. An exporter that declines to reduce is conformant: the data
// offset above them is ignored by instruction, and the reduced form covers
// the low octet alone.
func TestDecodeIPFIX_TCPControlBitsAtTwoOctets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wire uint16
		want uint8
	}{
		{"control bits alone", 0x0012, 0x12},
		{"the data offset above them", 0x5012, 0x12},
		{"a bit above them the reduced form cannot carry", 0x0112, 0x12},
		{"no bit set", 0x0000, 0x00},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()

			template := ipfixTemplateSet(
				ipfixSpec(fieldProtocol, 1, 0),
				ipfixSpec(fieldTCPFlags, 2, 0),
			)
			record := be16([]byte{protocolTCP}, tt.wire)

			records, err := d.Decode(sentFrom(testExporter), ipfixMessage(0, template,
				flowSet(fixtureIPFIXTemplateID, record),
			), nil)
			if err != nil || len(records) != 1 {
				t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
			}

			if got := records[0].TCPFlags; got != tt.want {
				t.Errorf("TCPFlags = %#02x, want %#02x", got, tt.want)
			}
		})
	}
}

// TestDecodeIPFIX_DiffServCodePoint covers the element a record built on
// `match ipv4 dscp` exports in place of the TOS byte. IE 195 carries the six
// code-point bits right-aligned, where flow.Record holds the whole byte, so
// reading it without the shift would publish a class the wire never named.
func TestDecodeIPFIX_DiffServCodePoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		specs        [][]byte
		record       []byte
		wantTOS      uint8
		wantReported bool
	}{
		{
			name:         "the code point alone",
			specs:        [][]byte{ipfixSpec(fieldDSCP, 1, 0)},
			record:       []byte{46},
			wantTOS:      0xB8,
			wantReported: true,
		},
		{
			name:         "best effort is a value",
			specs:        [][]byte{ipfixSpec(fieldDSCP, 1, 0)},
			record:       []byte{0},
			wantTOS:      0x00,
			wantReported: true,
		},
		{
			name:         "a value wider than a code point is refused",
			specs:        [][]byte{ipfixSpec(fieldDSCP, 1, 0)},
			record:       []byte{64},
			wantTOS:      0x00,
			wantReported: false,
		},
		{
			name:         "the TOS byte outranks it, declared first",
			specs:        [][]byte{ipfixSpec(fieldSrcTOS, 1, 0), ipfixSpec(fieldDSCP, 1, 0)},
			record:       []byte{0x2E, 46},
			wantTOS:      0x2E,
			wantReported: true,
		},
		{
			name:         "the TOS byte outranks it, declared second",
			specs:        [][]byte{ipfixSpec(fieldDSCP, 1, 0), ipfixSpec(fieldSrcTOS, 1, 0)},
			record:       []byte{46, 0x2E},
			wantTOS:      0x2E,
			wantReported: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			records, err := d.Decode(sentFrom(testExporter), ipfixMessage(0,
				ipfixTemplateSet(tt.specs...),
				flowSet(fixtureIPFIXTemplateID, tt.record),
			), nil)
			if err != nil || len(records) != 1 {
				t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
			}

			if got := records[0].TOS; got != tt.wantTOS {
				t.Errorf("TOS = %#02x, want %#02x", got, tt.wantTOS)
			}
			if got := records[0].TOSReported; got != tt.wantReported {
				t.Errorf("TOSReported = %v, want %v", got, tt.wantReported)
			}
		})
	}
}

// TestDecodeIPFIX_BytesReported separates a byte count of zero from a record
// that carried none: the histogram observes the first and withholds the
// second, and only the flag tells them apart.
func TestDecodeIPFIX_BytesReported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		specs        [][]byte
		record       []byte
		wantBytes    uint64
		wantReported bool
	}{
		{
			name:   "no counter element",
			specs:  [][]byte{ipfixSpec(fieldIPv4SrcAddr, 4, 0)},
			record: []byte{10, 0, 0, 1},
		},
		{
			name:         "octetDeltaCount reports zero",
			specs:        [][]byte{ipfixSpec(fieldInBytes, 4, 0)},
			record:       be32(nil, 0),
			wantReported: true,
		},
		{
			// RFC 7011 section 6.2 allows any width from one to eight
			// octets, so the odd widths carry a reading like the rest.
			name:         "octetDeltaCount in three octets",
			specs:        [][]byte{ipfixSpec(fieldInBytes, 3, 0)},
			record:       []byte{0, 0x02, 0xBC},
			wantBytes:    700,
			wantReported: true,
		},
		{
			name:         "postOctetDeltaCount alone",
			specs:        [][]byte{ipfixSpec(fieldOutBytes, 4, 0)},
			record:       be32(nil, 700),
			wantBytes:    700,
			wantReported: true,
		},
		{
			// Both counters on one bidirectional template: summing them
			// would double the flow, so the ingress reading is the record's.
			name: "octetDeltaCount wins over postOctetDeltaCount",
			specs: [][]byte{
				ipfixSpec(fieldInBytes, 4, 0),
				ipfixSpec(fieldOutBytes, 4, 0),
			},
			record:       be32(be32(nil, 300), 700),
			wantBytes:    300,
			wantReported: true,
		},
		{
			name:         "postOctetDeltaCount in three octets",
			specs:        [][]byte{ipfixSpec(fieldOutBytes, 3, 0)},
			record:       []byte{0, 0x02, 0xBC},
			wantBytes:    700,
			wantReported: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			records, err := d.Decode(sentFrom(testExporter), ipfixMessage(0,
				ipfixTemplateSet(tt.specs...),
				flowSet(fixtureIPFIXTemplateID, tt.record),
			), nil)
			if err != nil || len(records) != 1 {
				t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
			}

			if got := records[0].Bytes; got != tt.wantBytes {
				t.Errorf("Bytes = %d, want %d", got, tt.wantBytes)
			}
			if got := records[0].BytesReported; got != tt.wantReported {
				t.Errorf("BytesReported = %v, want %v", got, tt.wantReported)
			}
		})
	}
}
