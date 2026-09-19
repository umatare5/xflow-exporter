package decoder

import (
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const directionTemplateID = 820

// directionTemplate announces a flow template carrying the observation point.
func directionTemplate(carried bool) []byte {
	fields := [][2]uint16{{fieldIPv4SrcAddr, 4}, {fieldIPv4DstAddr, 4}, {fieldInBytes, 4}}
	if carried {
		fields = append(fields, [2]uint16{fieldFlowDirection, 1})
	}
	return flowSet(templateFlowSetID, templateSpec(directionTemplateID, fields...))
}

func directionRecord(direction byte, carried bool) []byte {
	record := be32([]byte{192, 0, 2, 10, 192, 0, 2, 20}, 1000)
	if carried {
		record = append(record, direction)
	}
	return record
}

// TestFlowDirection_ReadsTheObservationPointIE61Names pins the element RFC
// 7011 makes part of a flow's identity. A device watching one path at both
// ends reports the same traffic twice, and without the point the two readings
// share a key and read as one flow of twice the size.
func TestFlowDirection_ReadsTheObservationPointIE61Names(t *testing.T) {
	t.Parallel()

	const odid = 910

	tests := []struct {
		name    string
		carried bool
		value   byte
		want    flow.Direction
	}{
		{name: "ingress", carried: true, value: 0, want: flow.DirectionIngress},
		{name: "egress", carried: true, value: 1, want: flow.DirectionEgress},
		{
			// RFC 5102 assigns two values, so a third is a device writing
			// something the element does not define.
			name: "a value the element does not define", carried: true, value: 2,
			want: flow.DirectionUnknown,
		},
		{name: "a template carrying no point", want: flow.DirectionUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decodeSampling(t, d, v9Packet(1, odid, directionTemplate(tc.carried)))
			records := decodeSampling(t, d, v9Packet(2, odid,
				flowSet(directionTemplateID, directionRecord(tc.value, tc.carried))))

			if len(records) != 1 {
				t.Fatalf("Decode() returned %d records, want 1", len(records))
			}
			if got := records[0].Direction; got != tc.want {
				t.Errorf("Direction = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestSFlowDirection_DerivesThePointFromTheSampledSource pins the derivation
// sFlow leaves to the collector. Section 2.1 has a packet crossing two
// sampled sources yield a record from each, so the source is the only thing
// that separates the two readings -- and a source naming neither interface,
// or both, names no one point to separate them by.
func TestSFlowDirection_DerivesThePointFromTheSampledSource(t *testing.T) {
	t.Parallel()

	const (
		ifIndexSource = uint64(sflowSourceIfIndex) << 32
		vlanSource    = uint64(1) << 32
	)

	tests := []struct {
		name              string
		source            uint64
		inputIf, outputIf uint32
		want              flow.Direction
	}{
		{
			name: "the input alone", source: ifIndexSource | 10, inputIf: 10, outputIf: 9,
			want: flow.DirectionIngress,
		},
		{
			name: "the output alone", source: ifIndexSource | 10, inputIf: 9, outputIf: 10,
			want: flow.DirectionEgress,
		},
		{
			// An interface the sample left unnamed reads zero, which is no
			// ifIndex, so the other side still decides.
			name: "the output with the input unnamed", source: ifIndexSource | 10,
			inputIf: 0, outputIf: 10, want: flow.DirectionEgress,
		},
		{
			name: "a hairpin", source: ifIndexSource | 10, inputIf: 10, outputIf: 10,
			want: flow.DirectionUnknown,
		},
		{
			name: "neither interface", source: ifIndexSource | 11, inputIf: 10, outputIf: 9,
			want: flow.DirectionUnknown,
		},
		{
			name: "every port on the agent", source: ifIndexSource, inputIf: 0, outputIf: 10,
			want: flow.DirectionUnknown,
		},
		{
			name: "a VLAN source", source: vlanSource | 10, inputIf: 10, outputIf: 9,
			want: flow.DirectionUnknown,
		},
	}

	for _, tc := range tests {
		if got := sflowDirection(tc.source, tc.inputIf, tc.outputIf); got != tc.want {
			t.Errorf("%s: sflowDirection() = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// sflowFlowSampleBodyFrom builds a flow sample taken on one data source,
// which the shared fixture leaves as a VLAN source no direction derives from.
func sflowFlowSampleBodyFrom(source, input, output uint32, records ...[]byte) []byte {
	p := be32(nil, 900) // sample sequence
	p = be32(p, source)
	p = be32(p, 1000)      // sampling rate
	p = be32(p, 1_000_000) // sample pool
	p = be32(p, 2)         // drops
	p = be32(p, input)
	p = be32(p, output)
	p = be32(p, uint32(len(records)))
	for _, r := range records {
		p = append(p, r...)
	}
	return p
}

// TestDecodeSFlowV5_CarriesTheDerivedDirection pins the derivation through
// the decode path, the wire carrying the source and the interfaces apart.
func TestDecodeSFlowV5_CarriesTheDerivedDirection(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		source        uint32
		input, output uint32
		want          flow.Direction
	}{
		{
			name: "sampled on the port it entered", source: 10, input: 10, output: 9,
			want: flow.DirectionIngress,
		},
		{
			name: "sampled on the port it left", source: 10, input: 9, output: 10,
			want: flow.DirectionEgress,
		},
		{
			name: "sampled on a VLAN", source: 0x01_00000A, input: 10, output: 9,
			want: flow.DirectionUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			datagram := sflowDatagram(1, sflowSample(sflowFlowSample,
				sflowFlowSampleBodyFrom(tc.source, tc.input, tc.output,
					rawHeaderRecord(tcpFrame(false), 1518))))

			records, err := d.Decode(sentFrom(testExporter), datagram, nil)
			if err != nil {
				t.Fatalf("Decode() error = %v, want nil", err)
			}
			if len(records) != 1 {
				t.Fatalf("Decode() returned %d records, want 1", len(records))
			}
			if got := records[0].Direction; got != tc.want {
				t.Errorf("Direction = %s, want %s", got, tc.want)
			}
		})
	}
}
