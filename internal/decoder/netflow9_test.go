package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// v9 fixture constants. The export time and uptime anchor the flow clocks.
const (
	fixtureV9SysUptimeMs = 120_000
	fixtureV9ExportSecs  = 1_756_300_000
	fixtureV9ODID        = 256
	fixtureV9TemplateID  = 300
)

// v9Packet builds one v9 datagram from flowsets.
func v9Packet(sequence, odid uint32, flowSets ...[]byte) []byte {
	payload := make([]byte, netflowV9HeaderLen)
	binary.BigEndian.PutUint16(payload[0:2], 9)
	count := 0
	for _, set := range flowSets {
		count++ // The header count is records, but nothing may trust it.
		payload = append(payload, set...)
	}
	binary.BigEndian.PutUint16(payload[2:4], uint16(count))
	binary.BigEndian.PutUint32(payload[4:8], fixtureV9SysUptimeMs)
	binary.BigEndian.PutUint32(payload[8:12], fixtureV9ExportSecs)
	binary.BigEndian.PutUint32(payload[12:16], sequence)
	binary.BigEndian.PutUint32(payload[16:20], odid)
	return payload
}

// flowSet wraps records into one flowset with id and length.
func flowSet(id uint16, body ...[]byte) []byte {
	set := make([]byte, flowSetHeaderLen)
	binary.BigEndian.PutUint16(set[0:2], id)
	for _, part := range body {
		set = append(set, part...)
	}
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	return set
}

// templateSpec writes one template announcement body.
func templateSpec(templateID uint16, fields ...[2]uint16) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], templateID)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(fields)))
	for _, f := range fields {
		var spec [4]byte
		binary.BigEndian.PutUint16(spec[0:2], f[0])
		binary.BigEndian.PutUint16(spec[2:4], f[1])
		body = append(body, spec[:]...)
	}
	return body
}

// fixtureV9Template announces the IPv4 template every happy-path test uses.
func fixtureV9Template() []byte {
	return flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldIPv4SrcAddr, 4},
		[2]uint16{fieldIPv4DstAddr, 4},
		[2]uint16{fieldL4SrcPort, 2},
		[2]uint16{fieldL4DstPort, 2},
		[2]uint16{fieldProtocol, 1},
		[2]uint16{fieldSrcTOS, 1},
		[2]uint16{fieldTCPFlags, 1},
		[2]uint16{fieldSrcMask, 1},
		[2]uint16{fieldDstMask, 1},
		[2]uint16{fieldInputSNMP, 4},
		[2]uint16{fieldOutputSNMP, 4},
		[2]uint16{fieldInBytes, 4},
		[2]uint16{fieldInPackets, 4},
		[2]uint16{fieldSrcAS, 4},
		[2]uint16{fieldDstAS, 4},
		[2]uint16{fieldFirstSwitched, 4},
		[2]uint16{fieldLastSwitched, 4},
	))
}

// fixtureV9DataRecord writes one record matching fixtureV9Template.
func fixtureV9DataRecord() []byte {
	record := make([]byte, 0, 45)
	record = append(record, 10, 0, 0, 1, 198, 51, 100, 7) // src addr, dst addr
	record = be16(record, 51234)                          // src port
	record = be16(record, 443)                            // dst port
	record = append(record, 6, 0xB8, 0x1B, 24, 25)        // proto, tos, flags, masks
	record = be32(record, 3)                              // input
	record = be32(record, 4)                              // output
	record = be32(record, 512000)                         // bytes
	record = be32(record, 1000)                           // packets
	record = be32(record, 64500)                          // src as
	record = be32(record, 64501)                          // dst as
	record = be32(record, 30_000)                         // first switched
	record = be32(record, 45_000)                         // last switched
	return record
}

func be16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func be32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// fixtureV9Want is the record fixtureV9DataRecord decodes to.
func fixtureV9Want() flow.Record {
	bootTime := time.Unix(fixtureV9ExportSecs, 0).Add(-fixtureV9SysUptimeMs * time.Millisecond)
	return flow.Record{
		Exporter:         testExporter,
		Version:          flow.VersionNetFlowV9,
		SrcAddr:          netip.MustParseAddr("10.0.0.1"),
		DstAddr:          netip.MustParseAddr("198.51.100.7"),
		SrcPort:          51234,
		DstPort:          443,
		Protocol:         6,
		TOS:              0xB8,
		TOSReported:      true,
		TCPFlags:         0x1B,
		TCPFlagsReported: true,
		InputIf:          3,
		OutputIf:         4,
		Bytes:            512000,
		Packets:          1000,
		Flows:            1,
		SrcAS:            64500,
		DstAS:            64501,
		SrcMask:          24,
		DstMask:          25,
		Start:            bootTime.Add(30_000 * time.Millisecond),
		End:              bootTime.Add(45_000 * time.Millisecond),
	}
}

func TestDecodeNetFlowV9_TemplateThenData(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// Template and data can share one datagram, template first.
	packet := v9Packet(1, fixtureV9ODID,
		fixtureV9Template(),
		flowSet(fixtureV9TemplateID, fixtureV9DataRecord()),
	)

	records, err := d.Decode(testExporter, packet, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	if got, want := records[0], fixtureV9Want(); got != want {
		t.Errorf("Decode() record =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDecodeNetFlowV9_TemplatePersistsAcrossDatagrams(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
		t.Fatalf("template datagram error = %v, want nil", err)
	}

	records, err := d.Decode(testExporter,
		v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord(), fixtureV9DataRecord())), nil)
	if err != nil {
		t.Fatalf("data datagram error = %v, want nil", err)
	}
	if len(records) != 2 {
		t.Errorf("Decode() returned %d records, want 2 from the cached template", len(records))
	}
}

// TestDecodeNetFlowV9_TemplatesAreScopedPerDomain is the collision regression
// the template store exists for: two observation domains reusing one template
// ID must not overwrite each other, and neither must two exporters.
func TestDecodeNetFlowV9_TemplatesAreScopedPerDomain(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	otherExporter := netip.MustParseAddr("192.0.2.2")

	// Domain A announces the 45-byte fixture template under ID 300.
	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
		t.Fatalf("domain A template error = %v, want nil", err)
	}

	// Domain B on the same exporter reuses ID 300 for a different, 8-byte
	// layout. If the caches collided this would overwrite domain A.
	shortTemplate := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldInBytes, 4},
		[2]uint16{fieldInPackets, 4},
	))
	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID+1, shortTemplate), nil); err != nil {
		t.Fatalf("domain B template error = %v, want nil", err)
	}

	// A third domain on another exporter also reuses ID 300.
	if _, err := d.Decode(otherExporter, v9Packet(1, fixtureV9ODID, shortTemplate), nil); err != nil {
		t.Fatalf("exporter B template error = %v, want nil", err)
	}

	// Domain A must still decode with its own 45-byte template.
	records, err := d.Decode(testExporter,
		v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())), nil)
	if err != nil {
		t.Fatalf("domain A data error = %v, want nil", err)
	}
	if len(records) != 1 || records[0].Bytes != 512000 {
		t.Fatalf("domain A decoded %+v, want its own template applied", records)
	}

	// Domain B must decode the same set id with its own 8-byte layout.
	short := make([]byte, 0, 8)
	short = be32(short, 111)
	short = be32(short, 7)
	records, err = d.Decode(testExporter,
		v9Packet(2, fixtureV9ODID+1, flowSet(fixtureV9TemplateID, short)), nil)
	if err != nil {
		t.Fatalf("domain B data error = %v, want nil", err)
	}
	if len(records) != 1 || records[0].Bytes != 111 || records[0].Packets != 7 {
		t.Fatalf("domain B decoded %+v, want its own template applied", records)
	}
}

func TestDecodeNetFlowV9_MissingTemplateIsCountedNotFatal(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// One known and one unknown data flowset in a single datagram.
	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
		t.Fatalf("template error = %v, want nil", err)
	}

	packet := v9Packet(2, fixtureV9ODID,
		flowSet(999, []byte{1, 2, 3, 4}),
		flowSet(fixtureV9TemplateID, fixtureV9DataRecord()),
	)
	records, err := d.Decode(testExporter, packet, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the known flowset decoded", err)
	}
	if len(records) != 1 {
		t.Errorf("Decode() returned %d records, want 1 from the known flowset", len(records))
	}

	if got := errorCount(d, ReasonMissingTemplate); got != 1 {
		t.Errorf("missing_template count = %d, want 1", got)
	}
}

// errorCount reads one v9 error counter from the decoder's snapshot.
func errorCount(d *Decoder, reason string) uint64 {
	for _, snap := range d.Stats().Snapshot() {
		for _, e := range snap.Errors {
			if e.Version == flow.VersionNetFlowV9 && e.Reason == reason {
				return e.Count
			}
		}
	}
	return 0
}

func TestDecodeNetFlowV9_RejectsInvalidTemplates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		set  []byte
	}{
		{
			name: "zero-width field",
			set: flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
				[2]uint16{fieldInBytes, 0})),
		},
		{
			name: "template id in the reserved range",
			set:  flowSet(templateFlowSetID, templateSpec(255, [2]uint16{fieldInBytes, 4})),
		},
		{
			name: "zero fields",
			set:  flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID)),
		},
		{
			name: "field count past the limit",
			set: func() []byte {
				fields := make([][2]uint16, config.DefaultParserMaxFieldsPerTemplate+1)
				for i := range fields {
					fields[i] = [2]uint16{fieldInBytes, 1}
				}
				return flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID, fields...))
			}(),
		},
		{
			name: "specifiers cut short",
			set:  flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID, [2]uint16{fieldInBytes, 4})[:6]),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, tt.set), nil); err != nil {
				t.Fatalf("Decode() error = %v, want the datagram tolerated", err)
			}

			if got := errorCount(d, ReasonInvalidTemplate); got != 1 {
				t.Errorf("invalid_template count = %d, want 1", got)
			}

			// The refused template must not serve data.
			d2 := newTestDecoder()
			_, _ = d2.Decode(testExporter, v9Packet(1, fixtureV9ODID, tt.set), nil)
			_, _ = d2.Decode(testExporter,
				v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())), nil)
			if got := errorCount(d2, ReasonMissingTemplate); got != 1 {
				t.Errorf("missing_template count = %d, want the refused template absent", got)
			}
		})
	}
}

func TestDecodeNetFlowV9_TemplateExpiresAfterTTL(t *testing.T) {
	t.Parallel()

	d := New(config.Parser{MaxFieldsPerTemplate: 128, TemplateTTL: time.Minute})
	now := time.Unix(1_756_300_000, 0)
	d.templates.now = func() time.Time { return now }

	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
		t.Fatalf("template error = %v, want nil", err)
	}

	// Within the TTL the template serves.
	now = now.Add(30 * time.Second)
	records, _ := d.Decode(testExporter,
		v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())), nil)
	if len(records) != 1 {
		t.Fatalf("Decode() within TTL returned %d records, want 1", len(records))
	}

	// Past the TTL it must not: an orphaned template may describe a schema
	// the device replaced while unreachable.
	now = now.Add(2 * time.Minute)
	records, _ = d.Decode(testExporter,
		v9Packet(3, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())), nil)
	if len(records) != 0 {
		t.Errorf("Decode() past TTL returned %d records, want 0", len(records))
	}
	if got := errorCount(d, ReasonMissingTemplate); got != 1 {
		t.Errorf("missing_template count = %d, want 1 for the expired template", got)
	}
}

// v9OptionsTemplate assembles one options template under the given id from
// raw (type, length) pairs, splitting them at scopeFields.
func v9OptionsTemplate(id uint16, scopeFields int, specs ...[2]uint16) []byte {
	const specLen = 4

	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], uint16(scopeFields*specLen))
	binary.BigEndian.PutUint16(body[4:6], uint16((len(specs)-scopeFields)*specLen))
	for _, spec := range specs {
		body = be16(body, spec[0])
		body = be16(body, spec[1])
	}
	return flowSet(optionsTemplateFlowSetID, body)
}

// TestDecodeNetFlowV9_OptionsTemplateThatConsumesNothingIsRefused covers the
// options template every one of whose fields is a zero-length scope. A
// zero-length scope is legitimate on its own, so the field walk admits it,
// and a template made only of them describes a record of no bytes: the data
// sets naming it divided their length by that. One datagram of 42 bytes,
// needing no prior state, reached it.
func TestDecodeNetFlowV9_OptionsTemplateThatConsumesNothingIsRefused(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	packet := v9Packet(1, fixtureV9ODID,
		v9OptionsTemplate(300, 1, [2]uint16{1, 0}),
		flowSet(300, []byte{0, 0, 0, 0}),
	)
	records, err := d.Decode(testExporter, packet, nil)
	if err != nil || len(records) != 0 {
		t.Fatalf("Decode() = %d records, %v; want 0, nil", len(records), err)
	}
	if got := errorCount(d, ReasonInvalidTemplate); got != 1 {
		t.Errorf("invalid_template count = %d, want 1", got)
	}

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d domains, want 1", len(domains))
	}
	if domains[0].OptionsTemplates != 0 {
		t.Errorf("OptionsTemplates = %d, want the template not held", domains[0].OptionsTemplates)
	}
}

// TestDecodeNetFlowV9_ZeroLengthScopeBesideAnOptionFieldIsKept pins the other
// side of that rule: the bare system scope devices really send costs nothing
// on its own, and the template still describes the option fields beside it.
func TestDecodeNetFlowV9_ZeroLengthScopeBesideAnOptionFieldIsKept(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	packet := v9Packet(1, fixtureV9ODID,
		v9OptionsTemplate(501, 1,
			[2]uint16{1, 0},
			[2]uint16{fieldSamplingInterval, 4},
		),
		flowSet(501, be32(nil, 100)),
	)
	if _, err := d.Decode(testExporter, packet, nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d domains, want 1", len(domains))
	}
	if domains[0].OptionsTemplates != 1 {
		t.Errorf("OptionsTemplates = %d, want 1", domains[0].OptionsTemplates)
	}
	if domains[0].SamplingRate != 100 {
		t.Errorf("SamplingRate = %d, want the rate the option field carried", domains[0].SamplingRate)
	}
}

// TestDecodeNetFlowV9_OptionsScopeFieldIsRead pins that the scope area is
// read here as it is in the IPFIX reader. RFC 3954 numbers v9 scopes 1 to 5,
// none of which this exporter consumes, so a device spelling the application
// mapping the way RFC 6759 does is the only thing this changes -- and one
// rule across both readers is what keeps them from drifting.
func TestDecodeNetFlowV9_OptionsScopeFieldIsRead(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	const appID = 0x0D_00_00_2A // engine 13, selector 42
	const nameWidth = 16

	name := make([]byte, nameWidth)
	copy(name, "ms-office-365")

	record := be32(nil, appID)
	record = append(record, name...)

	packet := v9Packet(1, fixtureV9ODID,
		v9OptionsTemplate(502, 1,
			[2]uint16{fieldApplicationID, 4},
			[2]uint16{fieldApplicationName, nameWidth},
		),
		flowSet(502, record),
	)
	if _, err := d.Decode(testExporter, packet, nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	got, _ := d.apps.resolve(testExporter, appID)
	if got != "ms-office-365" {
		t.Errorf("resolve() = %q, want the name the scoped announcement carried", got)
	}
}

func TestDecodeNetFlowV9_OptionsDeclareSamplingRate(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// An options template with a 4-byte system scope, the sampler random
	// interval and the plain interval.
	optionsTemplate := func() []byte {
		body := make([]byte, 6)
		binary.BigEndian.PutUint16(body[0:2], 500) // template id
		binary.BigEndian.PutUint16(body[2:4], 4)   // scope section bytes
		binary.BigEndian.PutUint16(body[4:6], 8)   // option section bytes
		body = be16(body, 1)                       // scope: system
		body = be16(body, 4)
		body = be16(body, fieldSamplerRandomInterval)
		body = be16(body, 2)
		body = be16(body, fieldSamplingInterval)
		body = be16(body, 4)
		return flowSet(optionsTemplateFlowSetID, body)
	}()

	optionsRecord := func() []byte {
		record := make([]byte, 0, 10)
		record = be32(record, 9) // scope value
		record = be16(record, 1000)
		record = be32(record, 64)
		return record
	}()

	packet := v9Packet(1, fixtureV9ODID, optionsTemplate, flowSet(500, optionsRecord))
	records, err := d.Decode(testExporter, packet, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 0 {
		t.Fatalf("Decode() returned %d records, want options records to yield none", len(records))
	}

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d domains, want 1", len(domains))
	}
	if domains[0].SamplingRate != 1000 {
		t.Errorf("SamplingRate = %d, want the random interval 1000 preferred", domains[0].SamplingRate)
	}
	if domains[0].OptionsTemplates != 1 {
		t.Errorf("OptionsTemplates = %d, want 1", domains[0].OptionsTemplates)
	}

	// Flow records decoded after the options carry the rate.
	if _, err := d.Decode(testExporter, v9Packet(2, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
		t.Fatalf("template error = %v, want nil", err)
	}
	records, _ = d.Decode(testExporter,
		v9Packet(3, fixtureV9ODID, flowSet(fixtureV9TemplateID, fixtureV9DataRecord())), nil)
	if len(records) != 1 || records[0].SamplingRate != 1000 {
		t.Errorf("record sampling rate = %+v, want 1000 stamped from the domain", records)
	}
}

func TestDecodeNetFlowV9_SequenceGapsAreCounted(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	for _, seq := range []uint32{10, 11, 15, 14, 16} {
		_, _ = d.Decode(testExporter, v9Packet(seq, fixtureV9ODID, fixtureV9Template()), nil)
	}

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d domains, want 1", len(domains))
	}
	// 11→15 skips 12,13,14. The backwards 15→14 is reordering and is
	// ignored, so the following 16 counts nothing.
	if domains[0].SequenceMissed != 3 {
		t.Errorf("SequenceMissed = %d, want 3", domains[0].SequenceMissed)
	}
}

func TestDecodeNetFlowV9_AbsoluteClocksWinOverUptime(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldInBytes, 4},
		[2]uint16{fieldFirstSwitched, 4},
		[2]uint16{fieldLastSwitched, 4},
		[2]uint16{fieldFlowStartMilliseconds, 8},
		[2]uint16{fieldFlowEndMilliseconds, 8},
	))

	record := make([]byte, 0, 28)
	record = be32(record, 100)
	record = be32(record, 30_000)
	record = be32(record, 45_000)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], 1_756_300_100_000)
	record = append(record, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], 1_756_300_160_000)
	record = append(record, tmp[:]...)

	records, err := d.Decode(testExporter,
		v9Packet(1, fixtureV9ODID, tpl, flowSet(fixtureV9TemplateID, record)), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	if got := records[0].Start; !got.Equal(time.UnixMilli(1_756_300_100_000)) {
		t.Errorf("Start = %v, want the absolute clock", got)
	}
	if got := records[0].End; !got.Equal(time.UnixMilli(1_756_300_160_000)) {
		t.Errorf("End = %v, want the absolute clock", got)
	}
}

func TestDecodeNetFlowV9_RejectsBrokenStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "header cut short",
			payload: v9Packet(1, fixtureV9ODID)[:12],
		},
		{
			name: "flowset length below its header",
			payload: func() []byte {
				p := v9Packet(1, fixtureV9ODID, fixtureV9Template())
				binary.BigEndian.PutUint16(p[netflowV9HeaderLen+2:netflowV9HeaderLen+4], 3)
				return p
			}(),
		},
		{
			name: "flowset running past the datagram",
			payload: func() []byte {
				p := v9Packet(1, fixtureV9ODID, fixtureV9Template())
				binary.BigEndian.PutUint16(p[netflowV9HeaderLen+2:netflowV9HeaderLen+4], 60000)
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

func TestDecodeNetFlowV9_ReservedSetIsCounted(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, flowSet(2, []byte{0, 0, 0, 0})), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the datagram tolerated", err)
	}
	if got := errorCount(d, ReasonReservedSet); got != 1 {
		t.Errorf("reserved_set count = %d, want 1", got)
	}
}

func TestDecodeNetFlowV9_ToleratesTrailingPadding(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	payload := append(v9Packet(1, fixtureV9ODID, fixtureV9Template()), 0, 0, 0)
	if _, err := d.Decode(testExporter, payload, nil); err != nil {
		t.Errorf("Decode() error = %v, want trailing padding tolerated", err)
	}
}

func BenchmarkDecodeNetFlowV9(b *testing.B) {
	d := newTestDecoder()
	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
		b.Fatal(err)
	}

	records := make([]byte, 0, 45*20)
	for range 20 {
		records = append(records, fixtureV9DataRecord()...)
	}
	payload := v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, records))
	dst := make([]flow.Record, 0, 20)

	b.ReportAllocs()
	for b.Loop() {
		var err error
		dst, err = d.Decode(testExporter, payload, dst[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// appNameFieldLen is the fixed width an inline application name is exported
// at, padded with NULs the way a fixed-width string element is.
const appNameFieldLen = 32

// fixtureV9AppNameTemplate announces the fixture template with the inline
// application name element beside it, the shape a device exporting IE 96 per
// record uses.
func fixtureV9AppNameTemplate() []byte {
	return flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldIPv4SrcAddr, 4},
		[2]uint16{fieldIPv4DstAddr, 4},
		[2]uint16{fieldL4SrcPort, 2},
		[2]uint16{fieldL4DstPort, 2},
		[2]uint16{fieldProtocol, 1},
		[2]uint16{fieldSrcTOS, 1},
		[2]uint16{fieldTCPFlags, 1},
		[2]uint16{fieldSrcMask, 1},
		[2]uint16{fieldDstMask, 1},
		[2]uint16{fieldInputSNMP, 4},
		[2]uint16{fieldOutputSNMP, 4},
		[2]uint16{fieldInBytes, 4},
		[2]uint16{fieldInPackets, 4},
		[2]uint16{fieldSrcAS, 4},
		[2]uint16{fieldDstAS, 4},
		[2]uint16{fieldFirstSwitched, 4},
		[2]uint16{fieldLastSwitched, 4},
		[2]uint16{fieldApplicationName, appNameFieldLen},
	))
}

// fixtureV9AppNameDataRecord writes one record matching
// fixtureV9AppNameTemplate.
func fixtureV9AppNameDataRecord() []byte {
	name := make([]byte, appNameFieldLen)
	copy(name, "ms-office-365")
	return append(fixtureV9DataRecord(), name...)
}

// TestDecodeNetFlowV9_InlineApplicationName pins that the benchmark fixture
// below actually reaches the interner: a template without the element would
// measure a decode path the vendor strings never take.
func TestDecodeNetFlowV9_InlineApplicationName(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	records, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID,
		fixtureV9AppNameTemplate(),
		flowSet(fixtureV9TemplateID, fixtureV9AppNameDataRecord()),
	), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	if records[0].AppName != "ms-office-365" {
		t.Errorf("AppName = %q, want the padded inline name trimmed and carried", records[0].AppName)
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

// BenchmarkDecodeNetFlowV9AppName measures the decode path a record carrying
// an inline application name takes, one of the two paths vendor strings
// reach the interner by.
func BenchmarkDecodeNetFlowV9AppName(b *testing.B) {
	d := newTestDecoder()
	if _, err := d.Decode(testExporter, v9Packet(1, fixtureV9ODID, fixtureV9AppNameTemplate()), nil); err != nil {
		b.Fatal(err)
	}

	records := make([]byte, 0, (45+appNameFieldLen)*20)
	for range 20 {
		records = append(records, fixtureV9AppNameDataRecord()...)
	}
	payload := v9Packet(2, fixtureV9ODID, flowSet(fixtureV9TemplateID, records))
	dst := make([]flow.Record, 0, 20)

	b.ReportAllocs()
	for b.Loop() {
		var err error
		dst, err = d.Decode(testExporter, payload, dst[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
}
