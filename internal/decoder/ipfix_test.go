package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

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

	records, err := d.Decode(testExporter, message, nil)
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

				records, err := d.Decode(testExporter, message, nil)
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

			records, err := d.Decode(testExporter, message, nil)
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

	records, err := d.Decode(testExporter, message, nil)
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

	records, err := d.Decode(testExporter, message, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}

	want := flow.Record{
		Exporter: testExporter,
		Version:  flow.VersionIPFIX,
		SrcAddr:  netip.MustParseAddr("2001:db8::1"),
		DstAddr:  netip.MustParseAddr("2001:db8::2"),
		SrcPort:  51234,
		DstPort:  443,
		Protocol: 6,
		Bytes:    512000,
		Packets:  1000,
		Flows:    1,
		Start:    time.UnixMilli(1_756_400_100_000),
		End:      time.UnixMilli(1_756_400_160_000),
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

	records, err := d.Decode(testExporter, message, nil)
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

func TestDecodeIPFIX_VariableLengthOverrunIsCounted(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := ipfixTemplateSet(
		ipfixSpec(fieldApplicationName, variableFieldLength, 0),
	)

	// The record claims 200 bytes of value with 3 present.
	record := []byte{200, 'a', 'b', 'c'}
	message := ipfixMessage(0, tpl, flowSet(fixtureIPFIXTemplateID, record))

	records, err := d.Decode(testExporter, message, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the message tolerated", err)
	}
	if len(records) != 0 {
		t.Errorf("Decode() returned %d records, want 0 from the overrunning record", len(records))
	}
	if got := errorCountFor(d, flow.VersionIPFIX, ReasonMalformed); got != 1 {
		t.Errorf("malformed count = %d, want 1", got)
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

	records, err := d.Decode(testExporter, message, nil)
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

	records, err := d.Decode(testExporter, message, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("Decode() = %d records, %v; want 1, nil", len(records), err)
	}
	if records[0].AppID != 42 || records[0].AppName != "" || records[0].AppCategory != "" {
		t.Errorf("record = %+v, want the identifier kept and the strings absent", records[0])
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

	if _, err := d.Decode(testExporter, message, nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	domains := d.Domains()
	if len(domains) != 1 || domains[0].SamplingRate != 1000 {
		t.Errorf("Domains() = %+v, want sampling rate 1000 from the PSAMP pair", domains)
	}
}

func TestDecodeIPFIX_TemplateWithdrawal(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	announce := ipfixMessage(0, fixtureIPFIXTemplate())
	if _, err := d.Decode(testExporter, announce, nil); err != nil {
		t.Fatalf("announce error = %v, want nil", err)
	}
	if got := d.Domains()[0].Templates; got != 1 {
		t.Fatalf("Templates = %d, want 1 after the announcement", got)
	}

	withdrawBody := make([]byte, 4)
	binary.BigEndian.PutUint16(withdrawBody[0:2], fixtureIPFIXTemplateID)
	binary.BigEndian.PutUint16(withdrawBody[2:4], 0)
	withdraw := ipfixMessage(0, flowSet(ipfixTemplateSetID, withdrawBody))
	if _, err := d.Decode(testExporter, withdraw, nil); err != nil {
		t.Fatalf("withdraw error = %v, want nil", err)
	}

	if got := d.Domains()[0].Templates; got != 0 {
		t.Errorf("Templates = %d, want 0 after the withdrawal", got)
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

	if _, err := d.Decode(testExporter, first, nil); err != nil {
		t.Fatalf("first message error = %v, want nil", err)
	}
	if _, err := d.Decode(testExporter, second, nil); err != nil {
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
			records, err := d.Decode(testExporter, tt.payload, nil)
			if err == nil {
				t.Fatal("Decode() error = nil, want a malformed rejection")
			}
			if len(records) != 0 {
				t.Errorf("Decode() returned %d records alongside the error, want 0", len(records))
			}
		})
	}
}

// TestDecodeNetFlowV9_PanOSStringsAreCarried covers the PAN-OS application
// name, and pins that the User-ID beside it is skipped by its length rather
// than read: a user identity is high-cardinality and personally identifying,
// so no series carries it.
func TestDecodeNetFlowV9_PanOSStringsAreCarried(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	const fieldPanUserID = 56702

	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldInBytes, 4},
		[2]uint16{fieldPanAppID, 16},
		[2]uint16{fieldPanUserID, 16},
	))

	record := be32(nil, 4242)
	record = append(record, []byte("ssl\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")...)
	record = append(record, []byte("alice\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")...)

	records, err := d.Decode(testExporter,
		v9Packet(1, fixtureV9ODID, tpl, flowSet(fixtureV9TemplateID, record)), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	if records[0].AppName != "ssl" {
		t.Errorf("record = %+v, want the padded PAN-OS application name trimmed and carried", records[0])
	}
	if records[0].Bytes != 4242 {
		t.Errorf("Bytes = %d, want the User-ID skipped by length without desynchronizing", records[0].Bytes)
	}

	// A second record with the same strings must intern to the same backing.
	records2, _ := d.Decode(testExporter,
		v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, record)), nil)
	if len(records2) != 1 || records2[0].AppName != "ssl" {
		t.Fatalf("second decode = %+v, want the same strings", records2)
	}
}

func BenchmarkDecodeIPFIX(b *testing.B) {
	d := newTestDecoder()
	if _, err := d.Decode(testExporter, ipfixMessage(0, fixtureIPFIXTemplate()), nil); err != nil {
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
		dst, err = d.Decode(testExporter, payload, dst[:0])
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

// TestDecodeIPFIX_HonoursOptionsTemplateWithdrawal pins RFC 7011 section 8.1.
// A withdrawal record is four octets, the template id and a field count of
// zero, and carries no scope field count -- figure T, and figure V for the
// all-options form, whose set length is 8. The options reader claimed six
// octets per record, so a set carrying one withdrawal fell short of its own
// loop guard and was skipped whole, and a set carrying several advanced six
// octets per record instead of four. The data template reader, which is the
// same shape, has always been right.
func TestDecodeIPFIX_HonoursOptionsTemplateWithdrawal(t *testing.T) {
	t.Parallel()

	optionsHeld := func(t *testing.T, d *Decoder) int {
		t.Helper()
		domains := d.Domains()
		if len(domains) != 1 {
			t.Fatalf("Domains() returned %d domains, want 1", len(domains))
		}
		return domains[0].OptionsTemplates
	}

	announce := func() []byte {
		return ipfixMessage(0,
			ipfixOptionsTemplate(700,
				ipfixSpec(fieldApplicationID, 4, 0),
				ipfixSpec(fieldApplicationName, 8, 0)),
			ipfixOptionsTemplate(701,
				ipfixSpec(fieldApplicationID, 4, 0),
				ipfixSpec(fieldApplicationName, 8, 0)))
	}

	tests := []struct {
		name     string
		withdraw []byte
		want     int
	}{
		{
			name:     "one template id",
			withdraw: ipfixWithdrawal(ipfixOptionsTemplateSetID, 700),
			want:     1,
		},
		{
			name:     "several in one set",
			withdraw: ipfixWithdrawal(ipfixOptionsTemplateSetID, 700, 701),
			want:     0,
		},
		{
			name:     "all options templates",
			withdraw: ipfixWithdrawal(ipfixOptionsTemplateSetID, ipfixOptionsTemplateSetID),
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			if _, err := d.Decode(testExporter, announce(), nil); err != nil {
				t.Fatalf("Decode() error = %v, want the announcement accepted", err)
			}
			if got := optionsHeld(t, d); got != 2 {
				t.Fatalf("options templates held = %d, want 2 before the withdrawal", got)
			}

			if _, err := d.Decode(testExporter, ipfixMessage(1, tt.withdraw), nil); err != nil {
				t.Fatalf("Decode() error = %v, want the withdrawal accepted", err)
			}
			if got := optionsHeld(t, d); got != tt.want {
				t.Errorf("options templates held = %d, want %d", got, tt.want)
			}
		})
	}
}
