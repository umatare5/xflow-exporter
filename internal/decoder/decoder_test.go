package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

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
	d := New()
	d.now = func() time.Time { return at }

	records, err := d.Decode(testExporter, buildV5Packet(2), nil)
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

	d := New()

	// A structurally broken v5 datagram.
	broken := buildV5Packet(1)
	binary.BigEndian.PutUint16(broken[2:4], 0)
	if _, err := d.Decode(testExporter, broken, nil); err == nil {
		t.Fatal("Decode() error = nil, want a malformed rejection")
	}

	// A version nothing decodes.
	if _, err := d.Decode(testExporter, []byte{0x00, 0x07, 0x00, 0x00}, nil); err == nil {
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

func TestDecoder_DecodeRejectsSniffedButUnimplementedVersions(t *testing.T) {
	t.Parallel()

	d := New()

	payloads := map[string][]byte{
		"netflow_v8": {0x00, 0x08, 0x00, 0x01},
		"netflow_v9": {0x00, 0x09, 0x00, 0x00},
		"ipfix":      {0x00, 0x0A, 0x00, 0x10},
		"sflow_v5":   {0x00, 0x00, 0x00, 0x05},
	}

	for version, payload := range payloads {
		records, err := d.Decode(testExporter, payload, nil)
		if err == nil {
			t.Errorf("Decode(%s) error = nil, want unsupported until its milestone lands", version)
		}
		if len(records) != 0 {
			t.Errorf("Decode(%s) returned %d records, want 0", version, len(records))
		}
	}

	snap := d.Stats().Snapshot()[0]
	seen := map[string]bool{}
	for _, e := range snap.Errors {
		if e.Reason == ReasonUnsupportedVersion {
			seen[e.Version.String()] = true
		}
	}
	for version := range payloads {
		if !seen[version] {
			t.Errorf("no unsupported_version count for %s", version)
		}
	}
}

// TestDecoder_DecodeTruncatesPartialAppends pins that a failed decode leaves
// dst exactly as it was handed in, so a worker's reused slice never leaks
// half-parsed records into the next datagram.
func TestDecoder_DecodeTruncatesPartialAppends(t *testing.T) {
	t.Parallel()

	d := New()

	records, _ := d.Decode(testExporter, buildV5Packet(2), nil)
	if len(records) != 2 {
		t.Fatalf("seed decode returned %d records, want 2", len(records))
	}

	// A datagram that fails after the count is read: 3 claimed, bytes for 1.
	short := buildV5Packet(3)[:netflowV5HeaderLen+netflowV5RecordLen]

	records, err := d.Decode(testExporter, short, records)
	if err == nil {
		t.Fatal("Decode() error = nil, want a malformed rejection")
	}
	if len(records) != 2 {
		t.Errorf("Decode() left %d records, want the 2 it was handed", len(records))
	}
}

func TestStats_ExporterIsSharedAcrossVersions(t *testing.T) {
	t.Parallel()

	d := New()
	other := netip.MustParseAddr("192.0.2.2")

	if _, err := d.Decode(testExporter, buildV5Packet(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if _, err := d.Decode(other, buildV5Packet(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if got := len(d.Stats().Snapshot()); got != 2 {
		t.Errorf("Snapshot() returned %d exporters, want 2", got)
	}
}
