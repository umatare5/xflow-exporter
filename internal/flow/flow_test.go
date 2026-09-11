package flow

import (
	"math"
	"testing"
	"time"
)

func TestVersion_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version Version
		want    string
	}{
		{VersionUnknown, "unknown"},
		{VersionNetFlowV5, "netflow_v5"},
		{VersionNetFlowV8, "netflow_v8"},
		{VersionNetFlowV9, "netflow_v9"},
		{VersionIPFIX, "ipfix"},
		{VersionSFlowV5, "sflow_v5"},
		{Version(200), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := tt.version.String(); got != tt.want {
				t.Errorf("Version(%d).String() = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestRecord_Duration(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		record Record
		want   time.Duration
		wantOK bool
	}{
		{
			name:   "both instants present",
			record: Record{Start: start, End: start.Add(3 * time.Second)},
			want:   3 * time.Second,
			wantOK: true,
		},
		{
			name:   "zero duration is a reading",
			record: Record{Start: start, End: start},
			want:   0,
			wantOK: true,
		},
		{
			name:   "missing start withholds",
			record: Record{End: start},
			wantOK: false,
		},
		{
			name:   "missing both withholds",
			record: Record{},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tt.record.Duration()
			if ok != tt.wantOK {
				t.Fatalf("Duration() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("Duration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecord_Corrected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		record      Record
		wantBytes   uint64
		wantPackets uint64
	}{
		{
			name:        "no rate multiplies by one",
			record:      Record{Bytes: 1500, Packets: 2},
			wantBytes:   1500,
			wantPackets: 2,
		},
		{
			name:        "the rate in force scales both",
			record:      Record{Bytes: 1500, Packets: 2, SamplingRate: 50},
			wantBytes:   75000,
			wantPackets: 100,
		},
		{
			name:        "the largest product that fits",
			record:      Record{Bytes: math.MaxUint64 / 4, Packets: 1, SamplingRate: 4},
			wantBytes:   (math.MaxUint64 / 4) * 4,
			wantPackets: 4,
		},
		{
			name:        "a product past uint64 saturates",
			record:      Record{Bytes: 1 << 63, Packets: 1 << 63, SamplingRate: 2},
			wantBytes:   math.MaxUint64,
			wantPackets: math.MaxUint64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bytes, packets := tt.record.Corrected()
			if bytes != tt.wantBytes {
				t.Errorf("Corrected() bytes = %d, want %d", bytes, tt.wantBytes)
			}
			if packets != tt.wantPackets {
				t.Errorf("Corrected() packets = %d, want %d", packets, tt.wantPackets)
			}
		})
	}
}
