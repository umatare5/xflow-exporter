package decoder

import (
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const aggregateTemplateID = 810

// aggregateTemplate announces a flow template, with or without the element an
// aggregated cache declares its fold with.
func aggregateTemplate(folded bool) []byte {
	fields := [][2]uint16{{fieldIPv4SrcAddr, 4}, {fieldIPv4DstAddr, 4}, {fieldInBytes, 4}}
	if folded {
		fields = append(fields, [2]uint16{fieldDeltaFlowCount, 4})
	}
	return flowSet(templateFlowSetID, templateSpec(aggregateTemplateID, fields...))
}

func aggregateRecord(flows uint32, folded bool) []byte {
	record := be32([]byte{192, 0, 2, 10, 192, 0, 2, 20}, 1000)
	if folded {
		record = be32(record, flows)
	}
	return record
}

// domainAggregates reads what the zero-flow series is built from.
func domainAggregates(d *Decoder, odid uint32) (uint64, bool) {
	for _, snapshot := range d.Domains() {
		if snapshot.ODID == odid {
			return snapshot.AggregateZeroFlows, snapshot.AggregatesReported
		}
	}
	return 0, false
}

// TestDeltaFlowCount_ClassifiesByThePresenceOfTheElement pins the rule RFC
// 7015 sets. A mediator distributing one fold across start intervals reports
// the whole count on the first and zero on the rest, so reading the value
// would hand those continuations to the per-flow tables the fold already
// re-reports -- and a router exporting an aggregation cache over v9 escapes
// the version check that catches the same cache over v8.
func TestDeltaFlowCount_ClassifiesByThePresenceOfTheElement(t *testing.T) {
	t.Parallel()

	const odid = 900

	tests := []struct {
		name       string
		folded     bool
		flows      uint32
		wantFlows  uint64
		wantFolded bool
		wantZeros  uint64
	}{
		{name: "a per-flow template", folded: false, wantFlows: 1},
		{name: "a fold of many", folded: true, flows: 59, wantFlows: 59, wantFolded: true},
		{name: "a fold of one", folded: true, flows: 1, wantFlows: 1, wantFolded: true},
		{
			// The conservative count RFC 7015 section 5.2.1 gives a
			// continuation interval, which section 8.1 makes the default.
			name: "a fold reporting no flows", folded: true, flows: 0,
			wantFlows: 0, wantFolded: true, wantZeros: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decodeSampling(t, d, v9Packet(1, odid, aggregateTemplate(tc.folded)))
			records := decodeSampling(t, d, v9Packet(2, odid,
				flowSet(aggregateTemplateID, aggregateRecord(tc.flows, tc.folded))))

			if len(records) != 1 {
				t.Fatalf("Decode() returned %d records, want 1", len(records))
			}
			if got := records[0].Flows; got != tc.wantFlows {
				t.Errorf("Flows = %d, want %d", got, tc.wantFlows)
			}
			if got := records[0].Aggregated(); got != tc.wantFolded {
				t.Errorf("Aggregated() = %t, want %t", got, tc.wantFolded)
			}

			zeros, reported := domainAggregates(d, odid)
			if reported != tc.folded {
				t.Errorf("AggregatesReported = %t, want %t", reported, tc.folded)
			}
			if zeros != tc.wantZeros {
				t.Errorf("xflow_aggregate_zero_flows_total = %d, want %d", zeros, tc.wantZeros)
			}
		})
	}
}

// TestDeltaFlowCount_PartsOneDatagramsTemplates pins the classification to
// the record. A domain announcing a folded template beside a per-flow one
// sends both in a datagram, so judging the batch by its first record either
// routes the fold into the derived tables or keeps the per-flow records out.
func TestDeltaFlowCount_PartsOneDatagramsTemplates(t *testing.T) {
	t.Parallel()

	const odid = 901

	d := newTestDecoder()
	decodeSampling(t, d, v9Packet(1, odid, aggregateTemplate(true), samplingTemplate(false)))
	records := decodeSampling(t, d, v9Packet(2, odid,
		flowSet(aggregateTemplateID, aggregateRecord(7, true)),
		flowSet(samplingTemplateID, samplingRecord(0, false))))

	if len(records) != 2 {
		t.Fatalf("Decode() returned %d records, want 2", len(records))
	}
	if !records[0].Aggregated() {
		t.Error("the folded record reads as per-flow, want an aggregate")
	}
	if records[1].Aggregated() {
		t.Error("the per-flow record reads as an aggregate, want per-flow")
	}
	if got := []uint64{records[0].Flows, records[1].Flows}; got[0] != 7 || got[1] != 1 {
		t.Errorf("Flows = %v, want the declared 7 beside the implied 1", got)
	}
}

// TestDeltaFlowCount_ReadsTheWidthTheDeviceChose pins the reduced-size
// encoding RFC 7011 section 6.2 permits for a counter.
func TestDeltaFlowCount_ReadsTheWidthTheDeviceChose(t *testing.T) {
	t.Parallel()

	const odid = 902

	d := newTestDecoder()
	decodeSampling(t, d, v9Packet(1, odid, flowSet(templateFlowSetID,
		templateSpec(aggregateTemplateID, [2]uint16{fieldInBytes, 4}, [2]uint16{fieldDeltaFlowCount, 2}))))
	records := decodeSampling(t, d, v9Packet(2, odid,
		flowSet(aggregateTemplateID, be16(be32(nil, 1000), 513))))

	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	if got := records[0].Flows; got != 513 {
		t.Errorf("Flows = %d, want the two-octet 513", got)
	}
	if !records[0].Aggregated() {
		t.Error("Aggregated() = false, want the narrow element classified like the wide one")
	}
}

// aggregatedVersions guards the version arm against a record the wire never
// gave a flow count.
func TestRecord_AggregatedHoldsBothArms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version  flow.Version
		reported bool
		want     bool
	}{
		{version: flow.VersionNetFlowV8, want: true},
		{version: flow.VersionNetFlowV8, reported: true, want: true},
		{version: flow.VersionNetFlowV9, want: false},
		{version: flow.VersionNetFlowV9, reported: true, want: true},
		{version: flow.VersionIPFIX, reported: true, want: true},
		{version: flow.VersionNetFlowV5, want: false},
		{version: flow.VersionSFlowV5, want: false},
	}

	for _, tc := range tests {
		r := flow.Record{Version: tc.version, FlowsReported: tc.reported}
		if got := r.Aggregated(); got != tc.want {
			t.Errorf("Aggregated() = %t for %s with reported %t, want %t",
				got, tc.version, tc.reported, tc.want)
		}
	}
}
