package decoder

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	samplingTemplateID = 700
	samplingOptionsID  = 500
	// samplingODID carries the options; samplingDataODID carries data alone.
	samplingODID     = 256
	samplingDataODID = 257
)

// samplingOptionsTemplate announces a system-scoped sampler table, with or
// without the samplerId a data record names.
func samplingOptionsTemplate(named bool) []byte {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[0:2], samplingOptionsID)
	binary.BigEndian.PutUint16(body[2:4], 4)
	optionBytes := uint16(4)
	if named {
		optionBytes = 8
	}
	binary.BigEndian.PutUint16(body[4:6], optionBytes)
	body = be16(body, 1) // scope: system
	body = be16(body, 4)
	if named {
		body = be16(body, fieldSamplerID)
		body = be16(body, 4)
	}
	body = be16(body, fieldSamplerRandomInterval)
	body = be16(body, 4)
	return flowSet(optionsTemplateFlowSetID, body)
}

// samplingDeclaration builds one options datagram declaring rates, each entry
// a samplerId and its rate when named.
func samplingDeclaration(sequence uint32, named bool, entries ...[2]uint32) []byte {
	sets := make([][]byte, 0, len(entries)+1)
	if sequence == 1 {
		sets = append(sets, samplingOptionsTemplate(named))
	}
	for _, entry := range entries {
		record := be32(make([]byte, 0, 12), 9) // scope value
		if named {
			record = be32(record, entry[0])
		}
		sets = append(sets, flowSet(samplingOptionsID, be32(record, entry[1])))
	}
	return v9Packet(sequence, samplingODID, sets...)
}

func samplingTemplate(named bool) []byte {
	fields := [][2]uint16{{fieldIPv4SrcAddr, 4}, {fieldIPv4DstAddr, 4}, {fieldInBytes, 4}}
	if named {
		fields = append(fields, [2]uint16{fieldSamplerID, 4})
	}
	return flowSet(templateFlowSetID, templateSpec(samplingTemplateID, fields...))
}

func samplingRecord(samplerID uint32, named bool) []byte {
	record := be32([]byte{192, 0, 2, 10, 192, 0, 2, 20}, 1000)
	if named {
		record = be32(record, samplerID)
	}
	return record
}

func decodeSampling(t *testing.T, d *Decoder, packet []byte) []flow.Record {
	t.Helper()

	records, err := d.Decode(testExporter, packet, nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	return records
}

func domainRate(d *Decoder, odid uint32) uint32 {
	for _, snapshot := range d.Domains() {
		if snapshot.ODID == odid {
			return snapshot.SamplingRate
		}
	}
	return 0
}

// TestSamplingRate_ResolvesTheRateThatMeasuredTheRecord pins the fallback
// chain against the configurations a device exports. The two results are what
// corrects the record and what audits the correction: a rate applied with no
// series to read it by is a silent correction, and a series with no rate
// behind it is a fabricated one.
func TestSamplingRate_ResolvesTheRateThatMeasuredTheRecord(t *testing.T) {
	t.Parallel()

	options, data := uint32(samplingODID), uint32(samplingDataODID)
	named, plain := true, false

	tests := []struct {
		name       string
		declare    [][]byte
		odid       uint32
		named      bool
		samplerID  uint32
		wantRate   uint32
		wantSeries uint32
	}{
		{
			name:    "the sampler the record names",
			declare: [][]byte{samplingDeclaration(1, named, [2]uint32{1, 32})},
			odid:    options, named: true, samplerID: 1, wantRate: 32, wantSeries: 32,
		},
		{
			// The sampler id is a nonkey field the device may not collect, so
			// a table naming samplers does not mean the records do.
			name:    "a table of one, records naming none",
			declare: [][]byte{samplingDeclaration(1, named, [2]uint32{1, 32})},
			odid:    options, wantRate: 32, wantSeries: 32,
		},
		{
			name:    "a table of two, records naming none",
			declare: [][]byte{samplingDeclaration(1, named, [2]uint32{1, 32}, [2]uint32{2, 1024})},
			odid:    options, wantRate: 0, wantSeries: 0,
		},
		{
			name:    "a declaration naming no sampler",
			declare: [][]byte{samplingDeclaration(1, plain, [2]uint32{0, 32})},
			odid:    options, wantRate: 32, wantSeries: 32,
		},
		{
			// A stack member exports its own domain and the options arrive on
			// another, which the device gives no way to align.
			name:    "another domain declared it, naming a sampler",
			declare: [][]byte{samplingDeclaration(1, named, [2]uint32{1, 32})},
			odid:    data, wantRate: 32, wantSeries: 32,
		},
		{
			name:    "another domain declared it, naming none",
			declare: [][]byte{samplingDeclaration(1, plain, [2]uint32{0, 32})},
			odid:    data, wantRate: 32, wantSeries: 32,
		},
		{
			// Options arrive on the device's own timer, so records name a
			// sampler before its declaration lands. What is missing is the
			// announcement rather than the rate.
			name:    "a sampler not announced yet",
			declare: [][]byte{samplingDeclaration(1, named, [2]uint32{1, 32})},
			odid:    options, named: true, samplerID: 2, wantRate: 32, wantSeries: 32,
		},
		{
			name: "a rate redeclared",
			declare: [][]byte{
				samplingDeclaration(1, plain, [2]uint32{0, 32}),
				samplingDeclaration(2, plain, [2]uint32{0, 64}),
			},
			odid: options, wantRate: 64, wantSeries: 64,
		},
		{
			// The declaration a sibling domain inherits is the current one,
			// not the first to arrive.
			name: "a rate redeclared, read from another domain",
			declare: [][]byte{
				samplingDeclaration(1, plain, [2]uint32{0, 32}),
				samplingDeclaration(2, plain, [2]uint32{0, 64}),
			},
			odid: data, wantRate: 64, wantSeries: 64,
		},
		{
			name: "a named sampler's rate redeclared",
			declare: [][]byte{
				samplingDeclaration(1, named, [2]uint32{1, 32}),
				samplingDeclaration(2, named, [2]uint32{1, 64}),
			},
			odid: options, named: true, samplerID: 1, wantRate: 64, wantSeries: 64,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			for _, packet := range tc.declare {
				decodeSampling(t, d, packet)
			}
			decodeSampling(t, d, v9Packet(10, tc.odid, samplingTemplate(tc.named)))
			records := decodeSampling(t, d, v9Packet(11, tc.odid,
				flowSet(samplingTemplateID, samplingRecord(tc.samplerID, tc.named))))

			if len(records) != 1 {
				t.Fatalf("Decode() returned %d records, want 1", len(records))
			}
			if got := records[0].SamplingRate; got != tc.wantRate {
				t.Errorf("SamplingRate = %d, want %d", got, tc.wantRate)
			}
			if got := domainRate(d, tc.odid); got != tc.wantSeries {
				t.Errorf("xflow_sampling_rate = %d, want %d", got, tc.wantSeries)
			}
		})
	}
}

// TestSamplingRate_IsNotDecidedByDeclarationOrder pins the rate to the sampler
// each record names. Keying it on the domain gave every record the last
// declaration to arrive, so a device sampling one interface 1:32 and another
// 1:1024 corrected both by whichever options record came second.
func TestSamplingRate_IsNotDecidedByDeclarationOrder(t *testing.T) {
	t.Parallel()

	for _, order := range [][2][2]uint32{
		{{1, 32}, {2, 1024}},
		{{2, 1024}, {1, 32}},
	} {
		d := newTestDecoder()
		decodeSampling(t, d, samplingDeclaration(1, true, order[0], order[1]))
		decodeSampling(t, d, v9Packet(2, samplingODID, samplingTemplate(true)))

		records := decodeSampling(t, d, v9Packet(3, samplingODID,
			flowSet(samplingTemplateID, samplingRecord(1, true), samplingRecord(2, true))))
		if len(records) != 2 {
			t.Fatalf("Decode() returned %d records, want 2", len(records))
		}
		if records[0].SamplingRate != 32 || records[1].SamplingRate != 1024 {
			t.Errorf("declaring sampler %d first gave rates %d and %d, want 32 and 1024",
				order[0][0], records[0].SamplingRate, records[1].SamplingRate)
		}
	}
}

// TestSamplingRate_RefusesADeclarationPastTheBudget pins the table's bound.
// The samplerId is a wire field, so a sender sets how many a device declares.
func TestSamplingRate_RefusesADeclarationPastTheBudget(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	for sampler := range uint32(maxSamplersPerExporter + 2) {
		decodeSampling(t, d, samplingDeclaration(sampler+1, true, [2]uint32{sampler, 32}))
	}

	if got := d.DeclarationsRefused(); got != 2 {
		t.Errorf("DeclarationsRefused() = %d, want the two past the budget", got)
	}
	if got := len(d.Samplers()); got != maxSamplersPerExporter {
		t.Errorf("Samplers() = %d, want the budget", got)
	}
}

// TestSamplingRate_DropsADeclarationTheDeviceStoppedAnnouncing pins the table
// to what the device still announces. A sampler deleted and recreated carries
// a new id, so holding the old entry leaves the device reading as one
// declaring two rates: every record naming neither would go uncorrected for
// as long as the process ran.
func TestSamplingRate_DropsADeclarationTheDeviceStoppedAnnouncing(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	at := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	d.templates.now = func() time.Time { return at }

	decodeSampling(t, d, samplingDeclaration(1, true, [2]uint32{1, 32}))
	decodeSampling(t, d, v9Packet(2, samplingODID, samplingTemplate(false)))

	read := func(sequence uint32) uint32 {
		records := decodeSampling(t, d, v9Packet(sequence, samplingODID,
			flowSet(samplingTemplateID, samplingRecord(0, false))))
		return records[0].SamplingRate
	}
	if got := read(3); got != 32 {
		t.Fatalf("SamplingRate = %d, want 32 from the only declaration", got)
	}

	// The device renumbers its sampler, and keeps announcing the new one.
	at = at.Add(config.DefaultParserTemplateTTL + time.Minute)
	decodeSampling(t, d, samplingDeclaration(1, true, [2]uint32{2, 64}))
	decodeSampling(t, d, v9Packet(5, samplingODID, samplingTemplate(false)))
	if got := read(6); got != 0 {
		t.Errorf("SamplingRate = %d, want 0 while both declarations stand", got)
	}

	d.SweepDomains()
	if got := read(7); got != 64 {
		t.Errorf("SamplingRate = %d, want 64 once the abandoned entry went", got)
	}
	if got := domainRate(d, samplingODID); got != 64 {
		t.Errorf("xflow_sampling_rate = %d, want 64", got)
	}
	if got := len(d.Samplers()); got != 1 {
		t.Errorf("Samplers() = %d, want the one the device still announces", got)
	}
}

// TestSamplingRate_ClearsARateTheDeviceStoppedDeclaring pins the same rule on
// a declaration that named no sampler. The domain holds that rate for the
// record path, so a device that stops announcing one would otherwise keep
// correcting by it for as long as the process ran.
func TestSamplingRate_ClearsARateTheDeviceStoppedDeclaring(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	at := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	d.templates.now = func() time.Time { return at }

	decodeSampling(t, d, samplingDeclaration(1, false, [2]uint32{0, 128}))
	decodeSampling(t, d, v9Packet(2, samplingODID, samplingTemplate(false)))

	read := func(sequence uint32) uint32 {
		records := decodeSampling(t, d, v9Packet(sequence, samplingODID,
			flowSet(samplingTemplateID, samplingRecord(0, false))))
		return records[0].SamplingRate
	}
	if got := read(3); got != 128 {
		t.Fatalf("SamplingRate = %d, want 128 from the domain's own declaration", got)
	}

	at = at.Add(config.DefaultParserTemplateTTL + time.Minute)
	decodeSampling(t, d, v9Packet(4, samplingODID, samplingTemplate(false)))
	d.SweepDomains()

	if got := read(5); got != 0 {
		t.Errorf("SamplingRate = %d, want 0 once the declaration went", got)
	}
	if got := domainRate(d, samplingODID); got != 0 {
		t.Errorf("xflow_sampling_rate = %d, want none", got)
	}
}

// domainSampling reads what the audit series are built from.
func domainSampling(d *Decoder, odid uint32) (uint64, bool) {
	for _, snapshot := range d.Domains() {
		if snapshot.ODID == odid {
			return snapshot.SamplingUnresolved, snapshot.Sampled
		}
	}
	return 0, false
}

// TestSamplingUnresolved_CountsWhatNoDeclarationSettles pins the record-level
// fact no other series carries. A record taken uncorrected and one corrected
// at 1:1 publish the same counts, and the declarations behind them read alike.
func TestSamplingUnresolved_CountsWhatNoDeclarationSettles(t *testing.T) {
	t.Parallel()

	named := true

	tests := []struct {
		name       string
		declare    []byte
		wantCount  uint64
		wantSample bool
	}{
		{
			// Two rates leave the device with nothing it tied to the record,
			// so the counts pass through uncorrected.
			name:       "declarations disagree",
			declare:    samplingDeclaration(1, named, [2]uint32{1, 32}, [2]uint32{2, 1024}),
			wantCount:  1,
			wantSample: true,
		},
		{
			name:       "one declaration settles it",
			declare:    samplingDeclaration(1, named, [2]uint32{1, 32}),
			wantCount:  0,
			wantSample: true,
		},
		{
			// A device that never declared is not sampling, and the series
			// would otherwise copy xflow_flows_total for every such device.
			name:       "never declared",
			wantCount:  1,
			wantSample: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			if tc.declare != nil {
				decodeSampling(t, d, tc.declare)
			}
			decodeSampling(t, d, v9Packet(10, samplingODID, samplingTemplate(false)))
			decodeSampling(t, d, v9Packet(11, samplingODID,
				flowSet(samplingTemplateID, samplingRecord(0, false))))

			count, sampled := domainSampling(d, samplingODID)
			if count != tc.wantCount {
				t.Errorf("xflow_sampling_unresolved_flows_total = %d, want %d", count, tc.wantCount)
			}
			if sampled != tc.wantSample {
				t.Errorf("sampled = %t, want %t", sampled, tc.wantSample)
			}
		})
	}
}

// TestSamplerTable_StaysSampledAfterItsDeclarationsExpire pins the flag
// against the device that stops re-announcing. The rate goes, and the
// records it stops correcting are the ones worth counting.
func TestSamplerTable_StaysSampledAfterItsDeclarationsExpire(t *testing.T) {
	t.Parallel()

	table := &samplerTable{}
	if !table.declare(0, 0, false, 32, 100) {
		t.Fatal("declare() = false, want the first declaration held")
	}

	table.expire(200)

	if got := table.inherited.Load(); got != 0 {
		t.Errorf("inherited = %d after expiry, want none", got)
	}
	if !table.sampled.Load() {
		t.Error("sampled = false after expiry, want the device still known to sample")
	}
}

// TestSamplingUnresolved_SurvivesTheDeclarationExpiring pins the flag through
// the snapshot the collector reads. A device that stops re-announcing keeps
// the series, which is when the records worth counting start arriving.
func TestSamplingUnresolved_SurvivesTheDeclarationExpiring(t *testing.T) {
	t.Parallel()

	d := New(config.Parser{MaxFieldsPerTemplate: 128, TemplateTTL: time.Minute})
	now := time.Unix(1_756_600_000, 0)
	d.templates.now = func() time.Time { return now }

	decodeSampling(t, d, samplingDeclaration(1, true, [2]uint32{1, 32}))
	decodeSampling(t, d, v9Packet(10, samplingODID, samplingTemplate(false)))

	if _, sampled := domainSampling(d, samplingODID); !sampled {
		t.Fatal("sampled = false after a declaration, want true")
	}

	// The device stops re-announcing while its records keep the domain live.
	now = now.Add(2 * time.Minute)
	decodeSampling(t, d, v9Packet(11, samplingODID,
		flowSet(samplingTemplateID, samplingRecord(0, false))))
	d.SweepDomains()

	if got := domainRate(d, samplingODID); got != 0 {
		t.Errorf("xflow_sampling_rate = %d after the declaration expired, want none", got)
	}
	if _, sampled := domainSampling(d, samplingODID); !sampled {
		t.Error("sampled = false after the declaration expired, want the device still sampling")
	}
}

// TestSamplingUnresolved_RidesTheDeviceNotTheDomain pins the flag's scope. A
// stack member announces its samplers on one domain and exports records on
// another, so a flag kept per domain would miss the domain that exports.
func TestSamplingUnresolved_RidesTheDeviceNotTheDomain(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	decodeSampling(t, d, samplingDeclaration(1, true, [2]uint32{1, 32}, [2]uint32{2, 1024}))
	decodeSampling(t, d, v9Packet(10, samplingDataODID, samplingTemplate(false)))
	decodeSampling(t, d, v9Packet(11, samplingDataODID,
		flowSet(samplingTemplateID, samplingRecord(0, false))))

	count, sampled := domainSampling(d, samplingDataODID)
	if !sampled {
		t.Error("sampled = false on the exporting domain, want the device's own flag")
	}
	if count != 1 {
		t.Errorf("unresolved = %d, want the record taken uncorrected counted", count)
	}
}
