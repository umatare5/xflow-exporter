package decoder

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// note is one logged line naming unread elements.
type note struct {
	Template   uint16
	Port       uint16
	Elements   []string
	Suppressed int
}

// captureNotes points the decoder's log at a buffer and returns a reader of
// the notes written so far.
func captureNotes(d *Decoder) func() []note {
	var buf bytes.Buffer
	d.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	return func() []note {
		var notes []note
		for line := range bytes.Lines(buf.Bytes()) {
			var n note
			if json.Unmarshal(line, &n) == nil {
				notes = append(notes, n)
			}
		}
		return notes
	}
}

// TestNoteUnread_NamesTheElementsNoReaderConsumes pins the RFC 7011 section 9
// note: every element a template carries that no reader consumes, spelled
// behind its enterprise number where it has one, and nothing for a template
// read whole. A v9 scope numbers a scope type rather than an element.
func TestNoteUnread_NamesTheElementsNoReaderConsumes(t *testing.T) {
	t.Parallel()

	const odid = 7

	tests := []struct {
		name     string
		datagram []byte
		want     []string
	}{
		{
			name: "v9 data template",
			datagram: v9Packet(1, odid, flowSet(templateFlowSetID, templateSpec(300,
				[2]uint16{fieldIPv4SrcAddr, 4}, [2]uint16{15, 4}, [2]uint16{fieldInBytes, 4}, [2]uint16{234, 4}))),
			want: []string{"15", "234"},
		},
		{
			name:     "v9 data template read whole",
			datagram: v9Packet(1, odid, fixtureV9Template()),
		},
		{
			name: "v9 options template beside its system scope",
			datagram: v9Packet(1, odid, v9OptionsTemplate(301, 1,
				[2]uint16{1, 4}, [2]uint16{fieldSamplerID, 4}, [2]uint16{84, 40}, [2]uint16{49, 1},
				[2]uint16{fieldSamplerRandomInterval, 2})),
			want: []string{"84", "49"},
		},
		{
			name: "IPFIX data template with an enterprise element",
			datagram: ipfixMessage(1, ipfixTemplateSet(
				ipfixSpec(fieldIPv4SrcAddr, 4, 0), ipfixSpec(fieldCiscoAppCategory, 32, ciscoPEN))),
			want: []string{"9/12232"},
		},
		{
			name: "IPFIX options template scoped on the application",
			datagram: ipfixMessage(1, ipfixOptionsTemplate(302,
				ipfixSpec(fieldApplicationID, 4, 0), ipfixSpec(fieldApplicationName, 24, 0),
				ipfixSpec(94, 55, 0), ipfixSpec(fieldCiscoAppCategory, 32, ciscoPEN))),
			want: []string{"94"},
		},
		{
			name: "IPFIX options template scoped on the interface",
			datagram: ipfixMessage(1, ipfixOptionsTemplate(304,
				ipfixSpec(fieldInputSNMP, 4, 0), ipfixSpec(fieldSamplingInterval, 4, 0))),
		},
		{
			name: "IPFIX options template scoped on an unread element",
			datagram: ipfixMessage(1, ipfixOptionsTemplate(303,
				ipfixSpec(144, 4, 0), ipfixSpec(fieldSamplingInterval, 4, 0))),
			want: []string{"144"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			notes := captureNotes(d)
			if _, err := d.Decode(sentFrom(testExporter), tt.datagram, nil); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			got := notes()
			if tt.want == nil {
				if len(got) != 0 {
					t.Errorf("notes = %+v, want none for a template read whole", got)
				}
				return
			}
			if len(got) != 1 || !slices.Equal(got[0].Elements, tt.want) {
				t.Errorf("notes = %+v, want one naming %v", got, tt.want)
			}
		})
	}
}

// TestNoteUnread_LogsALayoutOnce pins RFC 7011 section 8.4: a refresh
// repeating the layout under its ID writes nothing, and a new layout under
// the same ID writes again.
func TestNoteUnread_LogsALayoutOnce(t *testing.T) {
	t.Parallel()

	const odid, id = 7, 300
	announce := func(fields ...[2]uint16) []byte {
		return v9Packet(1, odid, flowSet(templateFlowSetID, templateSpec(id, fields...)))
	}
	first := announce([2]uint16{fieldIPv4SrcAddr, 4}, [2]uint16{15, 4})
	changed := announce([2]uint16{fieldIPv4SrcAddr, 4}, [2]uint16{15, 4}, [2]uint16{234, 4})

	d := newTestDecoder()
	notes := captureNotes(d)
	for _, datagram := range [][]byte{first, first, changed} {
		if _, err := d.Decode(sentFrom(testExporter), datagram, nil); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
	}

	want := []note{
		{Template: id, Port: testPort, Elements: []string{"15"}},
		{Template: id, Port: testPort, Elements: []string{"15", "234"}},
	}
	got := notes()
	if !slices.EqualFunc(got, want, func(a, b note) bool {
		return a.Template == b.Template && a.Port == b.Port && slices.Equal(a.Elements, b.Elements)
	}) {
		t.Errorf("notes = %+v, want %+v", got, want)
	}
}

// TestNoteUnread_RetriesAWithheldNote pins a note the limit withholds: the
// layout stays unnoted, so its next refresh logs it with the count withheld,
// and the refresh after that writes nothing.
func TestNoteUnread_RetriesAWithheldNote(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	notes := captureNotes(d)
	at := time.Unix(1_800_000_000, 0).Truncate(time.Minute)
	d.now = func() time.Time { return at }
	for range maxNotesPerMinute {
		d.notes.admit(at)
	}

	announce := v9Packet(1, 7, flowSet(templateFlowSetID, templateSpec(300,
		[2]uint16{fieldIPv4SrcAddr, 4}, [2]uint16{15, 4})))
	for minute := range 3 {
		at = at.Add(time.Duration(minute) * time.Minute)
		if _, err := d.Decode(sentFrom(testExporter), announce, nil); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
	}

	got := notes()
	if len(got) != 1 || got[0].Suppressed != 1 || !slices.Equal(got[0].Elements, []string{"15"}) {
		t.Errorf("notes = %+v, want one naming [15] and the 1 withheld", got)
	}
}

// TestNoteUnread_WithheldNoteAllocatesNothing pins the cost of a note past
// the limit: a sender changing the layout with every datagram spends no
// allocation on names nobody will read.
//
//nolint:paralleltest // testing.AllocsPerRun panics inside a parallel test.
func TestNoteUnread_WithheldNoteAllocatesNothing(t *testing.T) {
	d := newTestDecoder()
	at := time.Unix(1_800_000_000, 0)
	d.now = func() time.Time { return at }
	for range maxNotesPerMinute {
		d.notes.admit(at)
	}

	fields := make([]templateField, 128)
	for i := range fields {
		fields[i] = templateField{fieldType: uint16(1000 + i), length: 4}
	}
	key := domainKey{exporter: testExporter, odid: 7, proto: flow.VersionNetFlowV9}
	tpl := &template{fields: fields}
	allocs := testing.AllocsPerRun(100, func() {
		if d.noteUnread(key, testPort, 300, tpl) {
			t.Error("noteUnread() settled a layout past the limit")
		}
	})
	if allocs != 0 {
		t.Errorf("noteUnread() allocated %.0f times past the limit, want none", allocs)
	}
}

// TestNoteLimiter_CapsEachMinute pins the process bound on the notes: past
// the cap a minute's notes are withheld and counted, and the next minute's
// first note carries the count.
func TestNoteLimiter_CapsEachMinute(t *testing.T) {
	t.Parallel()

	var l noteLimiter
	at := time.Unix(1_800_000_000, 0).Truncate(time.Minute)
	for i := range maxNotesPerMinute {
		if ok, _ := l.admit(at); !ok {
			t.Fatalf("admit() refused note %d, want %d admitted a minute", i+1, maxNotesPerMinute)
		}
	}
	if ok, _ := l.admit(at.Add(59 * time.Second)); ok {
		t.Fatal("admit() admitted a note past the cap")
	}

	ok, suppressed := l.admit(at.Add(time.Minute))
	if !ok || suppressed != 1 {
		t.Errorf("admit() = %v, %d next minute, want true, 1", ok, suppressed)
	}
}
