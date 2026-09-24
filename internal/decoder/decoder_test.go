package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// newTestDecoder builds a decoder with the default parser limits.
func newTestDecoder() *Decoder {
	return New(config.Parser{
		MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
		TemplateTTL:          config.DefaultParserTemplateTTL,
	})
}

func TestSniffVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		want    flow.Version
		wantErr bool
	}{
		{"netflow v5", []byte{0x00, 0x05, 0x00, 0x01}, flow.VersionNetFlowV5, false},
		{"netflow v8", []byte{0x00, 0x08, 0x00, 0x01}, flow.VersionNetFlowV8, false},
		{"netflow v9", []byte{0x00, 0x09, 0x00, 0x01}, flow.VersionNetFlowV9, false},
		{"ipfix", []byte{0x00, 0x0A, 0x00, 0x40}, flow.VersionIPFIX, false},
		{"sflow v5", []byte{0x00, 0x00, 0x00, 0x05}, flow.VersionSFlowV5, false},
		{"sflow older version", []byte{0x00, 0x00, 0x00, 0x02}, flow.VersionUnknown, true},
		{"unknown 16-bit version", []byte{0x00, 0x07, 0x00, 0x01}, flow.VersionUnknown, true},
		{"too short to sniff", []byte{0x00, 0x05}, flow.VersionUnknown, true},
		{"empty", nil, flow.VersionUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := sniffVersion(tt.payload)
			if (err != nil) != tt.wantErr {
				t.Fatalf("sniffVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("sniffVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecoder_DecodeAccountsSuccess(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	d := newTestDecoder()
	d.now = func() time.Time { return at }

	records, err := d.Decode(sentFrom(testExporter), buildV5Packet(2), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 2 {
		t.Fatalf("Decode() returned %d records, want 2", len(records))
	}

	snaps := d.Stats().Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("Snapshot() returned %d exporters, want 1", len(snaps))
	}
	snap := snaps[0]
	if snap.Exporter != testExporter {
		t.Errorf("Exporter = %v, want %v", snap.Exporter, testExporter)
	}
	if len(snap.Flows) != 1 || snap.Flows[0].Version != flow.VersionNetFlowV5 || snap.Flows[0].Count != 2 {
		t.Errorf("Flows = %+v, want 2 netflow_v5 records", snap.Flows)
	}
	if len(snap.Errors) != 0 {
		t.Errorf("Errors = %+v, want none", snap.Errors)
	}
	if snap.LastFlowUnixNano != at.UnixNano() {
		t.Errorf("LastFlowUnixNano = %d, want %d", snap.LastFlowUnixNano, at.UnixNano())
	}
}

func TestDecoder_DecodeAccountsRejections(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// A structurally broken v5 datagram.
	broken := buildV5Packet(1)
	binary.BigEndian.PutUint16(broken[2:4], 0)
	if _, err := d.Decode(sentFrom(testExporter), broken, nil); err == nil {
		t.Fatal("Decode() error = nil, want a malformed rejection")
	}

	// A version nothing decodes.
	if _, err := d.Decode(sentFrom(testExporter), []byte{0x00, 0x07, 0x00, 0x00}, nil); err == nil {
		t.Fatal("Decode() error = nil, want an unsupported version rejection")
	}

	snap := d.Stats().Snapshot()[0]
	if snap.LastFlowUnixNano != 0 {
		t.Errorf("LastFlowUnixNano = %d, want 0 with no successful decode", snap.LastFlowUnixNano)
	}

	counts := map[string]uint64{}
	for _, e := range snap.Errors {
		counts[e.Version.String()+"/"+e.Reason] = e.Count
	}
	if counts["netflow_v5/"+ReasonMalformed] != 1 {
		t.Errorf("malformed v5 count = %d, want 1", counts["netflow_v5/"+ReasonMalformed])
	}
	if counts["unknown/"+ReasonUnsupportedVersion] != 1 {
		t.Errorf("unsupported count = %d, want 1", counts["unknown/"+ReasonUnsupportedVersion])
	}
}

// TestDecoder_DecodeTruncatesPartialAppends pins that a failed decode leaves
// dst exactly as it was handed in, so a worker's reused slice never leaks
// half-parsed records into the next datagram.
func TestDecoder_DecodeTruncatesPartialAppends(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	records, _ := d.Decode(sentFrom(testExporter), buildV5Packet(2), nil)
	if len(records) != 2 {
		t.Fatalf("seed decode returned %d records, want 2", len(records))
	}

	// A datagram that fails after the count is read: 3 claimed, bytes for 1.
	short := buildV5Packet(3)[:netflowV5HeaderLen+netflowV5RecordLen]

	records, err := d.Decode(sentFrom(testExporter), short, records)
	if err == nil {
		t.Fatal("Decode() error = nil, want a malformed rejection")
	}
	if len(records) != 2 {
		t.Errorf("Decode() left %d records, want the 2 it was handed", len(records))
	}
}

func TestStats_ExporterIsSharedAcrossVersions(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	other := netip.MustParseAddr("192.0.2.2")

	if _, err := d.Decode(sentFrom(testExporter), buildV5Packet(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if _, err := d.Decode(sentFrom(other), buildV5Packet(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if got := len(d.Stats().Snapshot()); got != 2 {
		t.Errorf("Snapshot() returned %d exporters, want 2", got)
	}
}

// testPort is the source port every fixture datagram arrives on, one export
// process being all a test needs unless it is about the session split.
const testPort = 50000

// sentFrom is the transport session a fixture datagram arrives on.
func sentFrom(addr netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(addr, testPort)
}

// TestDecode_RefusedAnnouncementWithdrawsTheLayout pins RFC 3954 section 9 and
// RFC 7011 section 8.4 on the parser's refusals: a redefinition it cannot read
// still retires the layout its ID held, so the device's new data counts as
// missing its template rather than decoding against the old one, whether it
// shares the announcement's message or follows it.
func TestDecode_RefusedAnnouncementWithdrawsTheLayout(t *testing.T) {
	t.Parallel()

	const id = fixtureIPFIXTemplateID
	held := [][2]uint16{{fieldIPv4SrcAddr, 4}, {fieldInBytes, 4}}
	tooMany := make([][2]uint16, config.DefaultParserMaxFieldsPerTemplate+1)
	for i := range tooMany {
		tooMany[i] = [2]uint16{fieldInPackets, 1}
	}

	ipfixTemplate := func(fields [][2]uint16) []byte {
		specs := make([][]byte, len(fields))
		for i, f := range fields {
			specs[i] = ipfixSpec(f[0], f[1], 0)
		}
		return ipfixTemplateSet(specs...)
	}
	protocols := []struct {
		version  flow.Version
		message  func(seq uint32, sets ...[]byte) []byte
		template func(fields [][2]uint16) []byte
	}{
		{
			flow.VersionNetFlowV9,
			func(seq uint32, sets ...[]byte) []byte { return v9Packet(seq, fixtureIPFIXODID, sets...) },
			func(fields [][2]uint16) []byte { return flowSet(templateFlowSetID, templateSpec(id, fields...)) },
		},
		{flow.VersionIPFIX, ipfixMessage, ipfixTemplate},
	}
	refusals := map[string][][2]uint16{
		"more fields than the parser takes": tooMany,
		"a zero-width field":                {{fieldIPv4SrcAddr, 4}, {fieldIPv4DstAddr, 0}, {fieldInBytes, 4}},
	}
	// Two records of a three-field layout, which the held layout would read as
	// three, and a body no held record fits, which it would call malformed.
	bodies := map[string][]byte{
		"whole records": be32(be32(be32(be32(be32(be32(nil,
			0x0a000001), 0x0a000002), 1000), 0x0a000003), 0x0a000004), 2000),
		"a short body": {10, 0, 0, 1, 0},
	}

	for _, p := range protocols {
		for refusal, fields := range refusals {
			for body, data := range bodies {
				for _, together := range []bool{false, true} {
					d := newTestDecoder()
					decode := func(message []byte) []flow.Record {
						records, _ := d.Decode(sentFrom(testExporter), message, nil)
						return records
					}
					decode(p.message(1, p.template(held)))

					var records []flow.Record
					if together {
						records = decode(p.message(2, p.template(fields), flowSet(id, data)))
					} else {
						decode(p.message(2, p.template(fields)))
						records = decode(p.message(3, flowSet(id, data)))
					}

					name := p.version.String() + ", " + refusal + ", " + body
					if len(records) != 0 {
						t.Errorf("%s: Decode() = %d records, want none from a withdrawn layout", name, len(records))
					}
					for reason, want := range map[string]uint64{
						ReasonInvalidTemplate: 1, ReasonMissingTemplate: 1, ReasonMalformed: 0,
					} {
						if got := errorCountFor(d, p.version, reason); got != want {
							t.Errorf("%s, together %v: %s = %d, want %d", name, together, reason, got, want)
						}
					}
				}
			}
		}
	}
}

// TestDecodeNetFlowV9_RefusedOptionsTemplateWithdrawsTheLayout pins the same
// withdrawal where the refusal is the record length rather than the parser: an
// options template whose only field is a zero-length scope reads nothing.
func TestDecodeNetFlowV9_RefusedOptionsTemplateWithdrawsTheLayout(t *testing.T) {
	t.Parallel()

	const odid, id = 7, 300
	d := newTestDecoder()
	for seq, set := range [][]byte{
		flowSet(templateFlowSetID, templateSpec(id, [2]uint16{fieldIPv4SrcAddr, 4}, [2]uint16{fieldInBytes, 4})),
		v9OptionsTemplate(id, 1, [2]uint16{1, 0}),
	} {
		if _, err := d.Decode(sentFrom(testExporter), v9Packet(uint32(seq), odid, set), nil); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
	}

	records, err := d.Decode(sentFrom(testExporter),
		v9Packet(2, odid, flowSet(id, be32(be32(nil, 0x0a000001), 1000))), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(records) != 0 || errorCount(d, ReasonMissingTemplate) != 1 {
		t.Errorf("Decode() = %d records, missing_template %d, want none and 1",
			len(records), errorCount(d, ReasonMissingTemplate))
	}
}
