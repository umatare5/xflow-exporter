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

func TestDecodeIPFIX_NBARApplicationTableResolvesRecords(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// Options template: scope (1 field) + applicationId, name and the Cisco
	// category attribute.
	optionsBody := make([]byte, 6)
	binary.BigEndian.PutUint16(optionsBody[0:2], 600)
	binary.BigEndian.PutUint16(optionsBody[2:4], 4)                           // total fields
	binary.BigEndian.PutUint16(optionsBody[4:6], 1)                           // scope fields
	optionsBody = append(optionsBody, ipfixSpec(fieldApplicationID, 4, 0)...) // scope: app
	optionsBody = append(optionsBody, ipfixSpec(fieldApplicationID, 4, 0)...)
	optionsBody = append(optionsBody, ipfixSpec(fieldApplicationName, variableFieldLength, 0)...)
	optionsBody = append(optionsBody, ipfixSpec(fieldCiscoAppCategory, variableFieldLength, ciscoPEN)...)
	optionsTemplate := flowSet(ipfixOptionsTemplateSetID, optionsBody)

	appID := uint32(0x0D_00_00_2A) // engine 13, selector 42
	optionsRecord := be32(nil, appID)
	optionsRecord = be32(optionsRecord, appID)
	optionsRecord = append(optionsRecord, 5)
	optionsRecord = append(optionsRecord, []byte("https")...)
	optionsRecord = append(optionsRecord, 8)
	optionsRecord = append(optionsRecord, []byte("browsing")...)

	dataTemplate := ipfixTemplateSet(
		ipfixSpec(fieldInBytes, 4, 0),
		ipfixSpec(fieldApplicationID, 4, 0),
	)
	dataRecord := be32(nil, 999)
	dataRecord = be32(dataRecord, appID)

	message := ipfixMessage(0, optionsTemplate,
		flowSet(600, optionsRecord),
		dataTemplate,
		flowSet(fixtureIPFIXTemplateID, dataRecord),
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

func TestDecodeNetFlowV9_PanOSStringsAreCarried(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

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
	if records[0].AppName != "ssl" || records[0].User != "alice" {
		t.Errorf("record = %+v, want the padded PAN-OS strings trimmed and carried", records[0])
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
