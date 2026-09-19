package decoder

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// beforeWrap is the uptime a device reads ms milliseconds before its counter
// returns to zero.
func beforeWrap(ms uint32) uint32 { return -ms }

// v9ClockPacket builds a datagram carrying the uptime pair alone, under the
// header uptime the pair is measured against.
func v9ClockPacket(uptimeMs, firstMs, lastMs uint32) []byte {
	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldFirstSwitched, 4},
		[2]uint16{fieldLastSwitched, 4},
	))
	payload := v9Packet(1, fixtureV9ODID, tpl,
		flowSet(fixtureV9TemplateID, be32(be32(nil, firstMs), lastMs)))
	binary.BigEndian.PutUint32(payload[4:8], uptimeMs)
	return payload
}

// decodeOneRecord decodes one datagram and returns the single record it holds.
func decodeOneRecord(t *testing.T, d *Decoder, payload []byte) flow.Record {
	t.Helper()

	records, err := d.Decode(testExporter, payload, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	return records[0]
}

// oneDomain returns the snapshot of the single domain a fixture opened.
func oneDomain(t *testing.T, d *Decoder) DomainSnapshot {
	t.Helper()

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d domains, want 1", len(domains))
	}
	return domains[0]
}

// The uptime counter is 32-bit milliseconds, so an instant recorded before it
// returned to zero is nearer the export than the arithmetic difference says.
// The pair is anchored by modular age, which leaves an ordinary flow where it
// already was and brings a wrapped one back from its 49-day future.
func TestDecodeNetFlowV9_AnchorsUptimeByModularAge(t *testing.T) {
	t.Parallel()

	const exportSecs = fixtureV9ExportSecs
	tests := []struct {
		name                      string
		uptimeMs, firstMs, lastMs uint32
		wantStartOff, wantEndOff  time.Duration
	}{
		{"neither instant wrapped", 120_000, 30_000, 45_000, -90 * time.Second, -75 * time.Second},
		{
			"both instants behind the wrap", 100_000, beforeWrap(10_000), beforeWrap(5_000),
			-110 * time.Second, -105 * time.Second,
		},
		{
			"the flow straddles the wrap", 1_000, beforeWrap(1_000), 500,
			-2 * time.Second, -500 * time.Millisecond,
		},

		// The device's own clock runs ahead of the uptime its header states,
		// which is a small difference below the wrap rather than a large one
		// above it. An hour is where this exporter stops reading it that way.
		{
			"inside the skew tolerance", 120_000, 121_000, 122_000,
			time.Second, 2 * time.Second,
		},
		{
			"at the skew tolerance", 120_000, 120_000 + 3_600_000, 120_000 + 3_600_001,
			-time.Duration(uptimeWrapMs-3_600_000) * time.Millisecond,
			-time.Duration(uptimeWrapMs-3_600_001) * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := decodeOneRecord(t, newTestDecoder(), v9ClockPacket(tt.uptimeMs, tt.firstMs, tt.lastMs))
			exportAt := time.Unix(exportSecs, 0)

			if want := exportAt.Add(tt.wantStartOff); !r.Start.Equal(want) {
				t.Errorf("Start = %v, want %v", r.Start, want)
			}
			if want := exportAt.Add(tt.wantEndOff); !r.End.Equal(want) {
				t.Errorf("End = %v, want %v", r.End, want)
			}
		})
	}
}

// A flow ending before it begins is not a reading. Both instants go, because
// the duration is what reaches a series and one instant cannot carry it.
func TestDecodeNetFlowV9_WithholdsAndCountsAnInvertedClock(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	r := decodeOneRecord(t, d, v9ClockPacket(120_000, 45_000, 30_000))

	if !r.Start.IsZero() || !r.End.IsZero() {
		t.Errorf("Start = %v, End = %v, want both withheld", r.Start, r.End)
	}
	if _, ok := r.Duration(); ok {
		t.Error("Duration() reported a reading, want none")
	}

	domain := oneDomain(t, d)
	if domain.ClockInversions != 1 {
		t.Errorf("ClockInversions = %d, want 1", domain.ClockInversions)
	}
	if !domain.ClocksAnchored {
		t.Error("ClocksAnchored = false, want true: a pair was anchored")
	}
}

// The absolute elements need no anchoring, but a pair of them inverts the
// same way and reaches the same histogram, so the rule is the pair's rather
// than the anchor's.
func TestDecodeNetFlowV9_WithholdsAnInvertedAbsoluteClock(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
		[2]uint16{fieldFlowStartMilliseconds, 8},
		[2]uint16{fieldFlowEndMilliseconds, 8},
	))
	body := be64(be64(nil, 1_756_300_160_000), 1_756_300_100_000)
	r := decodeOneRecord(t, d, v9Packet(1, fixtureV9ODID, tpl,
		flowSet(fixtureV9TemplateID, body)))

	if !r.Start.IsZero() || !r.End.IsZero() {
		t.Errorf("Start = %v, End = %v, want both withheld", r.Start, r.End)
	}
	if domain := oneDomain(t, d); domain.ClockInversions != 1 {
		t.Errorf("ClockInversions = %d, want 1", domain.ClockInversions)
	}
}

// One element of the pair without the other is half a reading. Anchoring the
// absent half would date the flow from the device's boot, which no template
// declared and no operator could tell from a measurement.
func TestDecodeNetFlowV9_WithholdsAHalfDeclaredClock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		field uint16
	}{
		{"the start alone", fieldFirstSwitched},
		{"the end alone", fieldLastSwitched},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			tpl := flowSet(templateFlowSetID, templateSpec(fixtureV9TemplateID,
				[2]uint16{fieldInBytes, 4},
				[2]uint16{tt.field, 4},
			))
			r := decodeOneRecord(t, d, v9Packet(1, fixtureV9ODID, tpl,
				flowSet(fixtureV9TemplateID, be32(be32(nil, 100), 30_000))))

			if !r.Start.IsZero() || !r.End.IsZero() {
				t.Errorf("Start = %v, End = %v, want both withheld", r.Start, r.End)
			}
			if domain := oneDomain(t, d); domain.ClocksAnchored {
				t.Error("ClocksAnchored = true, want false: no pair was anchored")
			}
		})
	}
}

// IPFIX states no uptime in its header, so IE 160 is what the pair is
// measured against. The export uptime is derived rather than added to,
// because the boot instant is absolute while the pair is 32-bit: adding them
// drifts by a whole period once the flow's own uptime passes the range.
func TestDecodeIPFIX_AnchorsUptimeOnSystemInitTime(t *testing.T) {
	t.Parallel()

	const (
		exportMs = int64(fixtureIPFIXExportSecs) * 1000
		hourMs   = 3_600_000
	)
	tests := []struct {
		name                     string
		upForMs                  int64
		firstMs, lastMs          uint32
		wantStartOff, wantEndOff time.Duration
	}{
		{
			"an ordinary flow", hourMs, hourMs - 60_000, hourMs - 30_000,
			-60 * time.Second, -30 * time.Second,
		},

		// The header times the export in whole seconds, so an instant inside
		// the second it was sent in reads as up to 999 ms past the derived
		// uptime. The tolerance is what keeps that below the wrap.
		{
			"inside the exported second", hourMs, hourMs - 200, hourMs + 800,
			-200 * time.Millisecond, 800 * time.Millisecond,
		},

		// Past 49.7 days of uptime the pair has wrapped while IE 160 has not.
		// Adding the pair to the boot instant would date the flow a whole
		// period early; deriving the export uptime from it does not.
		{
			"the counter has wrapped since boot", uptimeWrapMs + hourMs, hourMs - 60_000, hourMs - 30_000,
			-60 * time.Second, -30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tpl := ipfixTemplateSet(
				ipfixSpec(fieldSystemInitTime, 8, 0),
				ipfixSpec(fieldFirstSwitched, 4, 0),
				ipfixSpec(fieldLastSwitched, 4, 0),
			)
			body := be32(be32(be64(nil, uint64(exportMs-tt.upForMs)), tt.firstMs), tt.lastMs)

			r := decodeOneRecord(t, newTestDecoder(),
				ipfixMessage(1, tpl, flowSet(fixtureIPFIXTemplateID, body)))
			exportAt := time.Unix(fixtureIPFIXExportSecs, 0)

			if want := exportAt.Add(tt.wantStartOff); !r.Start.Equal(want) {
				t.Errorf("Start = %v, want %v", r.Start, want)
			}
			if want := exportAt.Add(tt.wantEndOff); !r.End.Equal(want) {
				t.Errorf("End = %v, want %v", r.End, want)
			}
		})
	}
}

// Without IE 160 there is nothing to measure the pair against, and a record
// dated from the epoch would be a reading the device never took.
func TestDecodeIPFIX_WithholdsUptimeClocksWithoutSystemInitTime(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	tpl := ipfixTemplateSet(
		ipfixSpec(fieldFirstSwitched, 4, 0),
		ipfixSpec(fieldLastSwitched, 4, 0),
	)
	r := decodeOneRecord(t, d, ipfixMessage(1, tpl,
		flowSet(fixtureIPFIXTemplateID, be32(be32(nil, 30_000), 45_000))))

	if !r.Start.IsZero() || !r.End.IsZero() {
		t.Errorf("Start = %v, End = %v, want both withheld", r.Start, r.End)
	}
	if domain := oneDomain(t, d); domain.ClocksAnchored {
		t.Error("ClocksAnchored = true, want false: no pair was anchored")
	}
}

// v5 fixes the pair in its record layout, so every v5 domain measures one.
func TestDecodeNetFlowV5_AnchorsUptimeByModularAge(t *testing.T) {
	t.Parallel()

	payload := buildV5Packet(1)
	binary.BigEndian.PutUint32(payload[4:8], 100_000)
	record := payload[netflowV5HeaderLen:]
	binary.BigEndian.PutUint32(record[24:28], beforeWrap(10_000))
	binary.BigEndian.PutUint32(record[28:32], beforeWrap(5_000))

	d := newTestDecoder()
	r := decodeOneRecord(t, d, payload)
	exportAt := time.Unix(fixtureExportSecs, fixtureExportNanos)

	if want := exportAt.Add(-110 * time.Second); !r.Start.Equal(want) {
		t.Errorf("Start = %v, want %v", r.Start, want)
	}
	if want := exportAt.Add(-105 * time.Second); !r.End.Equal(want) {
		t.Errorf("End = %v, want %v", r.End, want)
	}
	if domain := oneDomain(t, d); !domain.ClocksAnchored {
		t.Error("ClocksAnchored = false, want true: a pair was anchored")
	}
}

// A v8 record is an aggregate, so its span reaches no series. The inversion
// is still withheld, and counting it would report a distortion the exporter
// never published.
func TestDecodeNetFlowV8_WithholdsAnInvertedClockUncounted(t *testing.T) {
	t.Parallel()

	record := make([]byte, 28)
	putV8Common(record)
	binary.BigEndian.PutUint32(record[12:16], fixtureV8LastMs)
	binary.BigEndian.PutUint32(record[16:20], fixtureV8FirstMs)

	d := newTestDecoder()
	r := decodeOneRecord(t, d, append(buildV8Header(1, 1), record...))

	if !r.Start.IsZero() || !r.End.IsZero() {
		t.Errorf("Start = %v, End = %v, want both withheld", r.Start, r.End)
	}

	domain := oneDomain(t, d)
	if domain.ClockInversions != 0 {
		t.Errorf("ClockInversions = %d, want 0", domain.ClockInversions)
	}
	if domain.ClocksAnchored {
		t.Error("ClocksAnchored = true, want false: an aggregate publishes no span")
	}
}
