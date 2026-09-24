package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	scopeOptionsID = 600
	scopeODID      = 7
)

// scopeCounters is the data template the scope tests send records under: the
// counters and the interface a scope can name.
var scopeCounters = [][2]uint16{{fieldInBytes, 4}, {fieldInPackets, 4}, {fieldInputSNMP, 4}}

// scopeRecord is one record under scopeCounters, arriving on inputIf.
func scopeRecord(inputIf uint32) []byte {
	return be32(be32(be32(nil, 100), 1), inputIf)
}

// scopedEntry is one options record: a scope value and the rate tied to it.
func scopedEntry(value, rate uint32, width int) []byte {
	b := make([]byte, width)
	switch width {
	case 2:
		binary.BigEndian.PutUint16(b, uint16(value))
	default:
		binary.BigEndian.PutUint32(b, value)
	}
	return be32(b, rate)
}

// scopeCase is one protocol's way of scoping a declaration and of carrying a
// data template and a record.
type scopeCase struct {
	packet  func(odid uint32, sets ...[]byte) []byte
	options []byte
	width   int
	tplSet  func(id uint16) []byte
}

func v9ScopeCase(scopeType, width uint16) scopeCase {
	return scopeCase{
		packet: func(odid uint32, sets ...[]byte) []byte { return v9Packet(1, odid, sets...) },
		options: v9OptionsTemplate(scopeOptionsID, 1,
			[2]uint16{scopeType, width}, [2]uint16{fieldSamplingInterval, 4}),
		width: int(width),
		tplSet: func(id uint16) []byte {
			return flowSet(templateFlowSetID, templateSpec(id, scopeCounters...))
		},
	}
}

func ipfixScopeCase(scopeField, width uint16) scopeCase {
	return scopeCase{
		packet: ipfixMessageOn,
		options: ipfixOptionsTemplate(scopeOptionsID,
			ipfixSpec(scopeField, width, 0), ipfixSpec(fieldSamplingInterval, 4, 0)),
		width: int(width),
		tplSet: func(id uint16) []byte {
			body := binary.BigEndian.AppendUint16(nil, id)
			body = binary.BigEndian.AppendUint16(body, uint16(len(scopeCounters)))
			for _, f := range scopeCounters {
				body = append(body, ipfixSpec(f[0], f[1], 0)...)
			}
			return flowSet(ipfixTemplateSetID, body)
		},
	}
}

// ipfixMessageOn is ipfixMessage for an observation domain of the caller's.
func ipfixMessageOn(odid uint32, sets ...[]byte) []byte {
	message := ipfixMessage(1, sets...)
	binary.BigEndian.PutUint32(message[12:16], odid)
	return message
}

// scopedRates decodes one record per template and returns the rate each took.
func scopedRates(t *testing.T, d *Decoder, tc scopeCase, odid uint32, ids ...uint16) []uint32 {
	t.Helper()

	rates := make([]uint32, 0, len(ids))
	for _, id := range ids {
		records := decodeSampling(t, d, tc.packet(odid, tc.tplSet(id), flowSet(id, scopeRecord(9))))
		if len(records) != 1 {
			t.Fatalf("template %d: Decode() returned %d records, want 1", id, len(records))
		}
		rates = append(rates, records[0].SamplingRate)
	}
	return rates
}

// TestSamplingRate_TemplateScopeCorrectsItsOwnTemplate pins a declaration
// scoped to one template to that template's records, whichever arrived last.
// A template the device scoped nothing to borrows no other template's rate:
// its record is owed one, so Juniper's per-family rates stay apart.
func TestSamplingRate_TemplateScopeCorrectsItsOwnTemplate(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]scopeCase{
		"v9 scope type 5":  v9ScopeCase(v9ScopeTemplate, 2),
		"IPFIX templateId": ipfixScopeCase(fieldTemplateID, 2),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decodeSampling(t, d, tc.packet(scopeODID, tc.options,
				flowSet(scopeOptionsID, scopedEntry(300, 100, tc.width), scopedEntry(301, 1000, tc.width))))

			got := scopedRates(t, d, tc, scopeODID, 300, 301, 302)
			if got[0] != 100 || got[1] != 1000 || got[2] != 0 {
				t.Errorf("rates = %v, want [100 1000 0]", got)
			}
			if count, sampled := domainSampling(d, scopeODID); count != 1 || !sampled {
				t.Errorf("unresolved = %d (sampled %t), want the unscoped template's record owed", count, sampled)
			}
			if rate := domainRate(d, scopeODID); rate != 0 {
				t.Errorf("domain rate = %d, want none for a device declaring per template", rate)
			}
		})
	}
}

// TestSamplingRate_TemplateScopeStaysInItsSession pins the scope to the
// transport session that announced the template: another export process
// numbering the same template ID is a different template.
func TestSamplingRate_TemplateScopeStaysInItsSession(t *testing.T) {
	t.Parallel()

	tc := v9ScopeCase(v9ScopeTemplate, 2)
	d := newTestDecoder()
	first := netip.AddrPortFrom(testExporter, 61301)
	second := netip.AddrPortFrom(testExporter, 63558)
	decode := func(from netip.AddrPort, sets ...[]byte) []flow.Record {
		records, err := d.Decode(from, tc.packet(scopeODID, sets...), nil)
		if err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
		return records
	}

	decode(first, tc.options, flowSet(scopeOptionsID, scopedEntry(300, 100, tc.width)))
	own := decode(first, tc.tplSet(300), flowSet(300, scopeRecord(9)))
	other := decode(second, tc.tplSet(300), flowSet(300, scopeRecord(9)))

	if len(own) != 1 || own[0].SamplingRate != 100 {
		t.Errorf("announcing session: records %+v, want rate 100", own)
	}
	if len(other) != 1 || other[0].SamplingRate != 0 {
		t.Errorf("other session: records %+v, want no rate from the first session's template", other)
	}
}

// TestSamplingRate_TemplateScopeBesideASystemScope pins a declaration to the
// narrowest of the scopes its options record carries.
func TestSamplingRate_TemplateScopeBesideASystemScope(t *testing.T) {
	t.Parallel()

	tc := v9ScopeCase(v9ScopeTemplate, 2)
	tc.options = v9OptionsTemplate(scopeOptionsID, 2,
		[2]uint16{1, 4}, [2]uint16{v9ScopeTemplate, 2}, [2]uint16{fieldSamplingInterval, 4})
	d := newTestDecoder()
	decodeSampling(t, d, tc.packet(scopeODID, tc.options,
		flowSet(scopeOptionsID, append(be32(nil, 0), scopedEntry(300, 100, 2)...))))

	if got := scopedRates(t, d, tc, scopeODID, 300, 301); got[0] != 100 || got[1] != 0 {
		t.Errorf("rates = %v, want [100 0]", got)
	}
}

// TestSamplingRate_InterfaceScopeCorrectsItsInterface pins a declaration scoped
// to one interface to the records arriving on it, RFC 3954 section 6.1's
// example of a scope below the device.
func TestSamplingRate_InterfaceScopeCorrectsItsInterface(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]scopeCase{
		"v9 scope type 2":        v9ScopeCase(v9ScopeInterface, 4),
		"IPFIX ingressInterface": ipfixScopeCase(fieldInputSNMP, 4),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := newTestDecoder()
			decodeSampling(t, d, tc.packet(scopeODID, tc.options,
				flowSet(scopeOptionsID, scopedEntry(5, 100, tc.width), scopedEntry(6, 1000, tc.width))))
			decodeSampling(t, d, tc.packet(scopeODID, tc.tplSet(300)))

			var got []uint32
			for _, inputIf := range []uint32{5, 6, 7} {
				records := decodeSampling(t, d, tc.packet(scopeODID, flowSet(300, scopeRecord(inputIf))))
				if len(records) != 1 {
					t.Fatalf("interface %d: Decode() returned %d records, want 1", inputIf, len(records))
				}
				got = append(got, records[0].SamplingRate)
			}
			if got[0] != 100 || got[1] != 1000 || got[2] != 0 {
				t.Errorf("rates = %v, want [100 1000 0]", got)
			}
		})
	}
}

// TestSamplingRate_DomainScopeCorrectsTheNamedDomain pins an IPFIX declaration
// scoped to another observation domain to that domain's records and rate,
// leaving the domain that carried it without one.
func TestSamplingRate_DomainScopeCorrectsTheNamedDomain(t *testing.T) {
	t.Parallel()

	const named = scopeODID + 1
	tc := ipfixScopeCase(fieldObservationDomainID, 4)
	d := newTestDecoder()
	decodeSampling(t, d, tc.packet(scopeODID, tc.options, flowSet(scopeOptionsID, scopedEntry(named, 100, 4))))

	if got := scopedRates(t, d, tc, named, 300); got[0] != 100 {
		t.Errorf("named domain's record rate = %d, want 100", got[0])
	}
	if got := scopedRates(t, d, tc, scopeODID, 300); got[0] != 0 {
		t.Errorf("declaring domain's record rate = %d, want none", got[0])
	}
	if rate := domainRate(d, named); rate != 100 {
		t.Errorf("named domain rate = %d, want the scoped 100", rate)
	}
}

// TestSamplingRate_DomainDeclarationStandsBesideAScopedOne pins the unscoped
// declaration to the records no scope names: they take the domain's rate
// rather than owing one.
func TestSamplingRate_DomainDeclarationStandsBesideAScopedOne(t *testing.T) {
	t.Parallel()

	tc := v9ScopeCase(v9ScopeTemplate, 2)
	d := newTestDecoder()
	decodeSampling(t, d, tc.packet(scopeODID, tc.options, flowSet(scopeOptionsID, scopedEntry(300, 100, tc.width))))
	decodeSampling(t, d, v9Packet(2, scopeODID,
		v9OptionsTemplate(scopeOptionsID+1, 1, [2]uint16{1, 4}, [2]uint16{fieldSamplingInterval, 4}),
		flowSet(scopeOptionsID+1, be32(be32(nil, 0), 50))))

	if got := scopedRates(t, d, tc, scopeODID, 300, 301); got[0] != 100 || got[1] != 50 {
		t.Errorf("rates = %v, want [100 50]", got)
	}
}

// TestSamplingRate_ScopedDeclarationsShareTheBudget pins the scoped table to
// the device's declaration budget: its scope values are wire fields.
func TestSamplingRate_ScopedDeclarationsShareTheBudget(t *testing.T) {
	t.Parallel()

	tc := v9ScopeCase(v9ScopeInterface, 4)
	d := newTestDecoder()
	decodeSampling(t, d, tc.packet(scopeODID, tc.options))
	for inputIf := range uint32(maxSamplersPerExporter + 2) {
		decodeSampling(t, d, tc.packet(scopeODID, flowSet(scopeOptionsID, scopedEntry(inputIf+1, 32, 4))))
	}

	if got := d.DeclarationsRefused(); got != 2 {
		t.Errorf("DeclarationsRefused() = %d, want the two past the budget", got)
	}
}

// TestSamplingRate_ScopedDeclarationExpires pins a scoped rate to the device
// still announcing it: once the sweep passes the TTL, the template's records
// are owed a rate rather than taking one the device stopped declaring.
func TestSamplingRate_ScopedDeclarationExpires(t *testing.T) {
	t.Parallel()

	tc := v9ScopeCase(v9ScopeTemplate, 2)
	d := New(config.Parser{MaxFieldsPerTemplate: 128, TemplateTTL: time.Minute})
	now := time.Unix(1_756_600_000, 0)
	d.templates.now = func() time.Time { return now }

	decodeSampling(t, d, tc.packet(scopeODID, tc.options, flowSet(scopeOptionsID, scopedEntry(300, 100, tc.width))))
	now = now.Add(2 * time.Minute)
	decodeSampling(t, d, tc.packet(scopeODID, tc.tplSet(300)))
	d.SweepDomains()

	if got := scopedRates(t, d, tc, scopeODID, 300); got[0] != 0 {
		t.Errorf("rate = %d after the declaration expired, want none", got[0])
	}
}
