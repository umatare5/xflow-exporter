package decoder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// ipfixHeaderOnly is the cheapest datagram that names an observation domain:
// a well-formed 16-byte header carrying no set at all.
func ipfixHeaderOnly(odid uint32) []byte {
	b := make([]byte, ipfixHeaderLen)
	binary.BigEndian.PutUint16(b[0:2], 10)
	binary.BigEndian.PutUint16(b[2:4], ipfixHeaderLen)
	binary.BigEndian.PutUint32(b[12:16], odid)
	return b
}

// TestTemplateStore_DomainsAreBoundedPerExporter is the regression test for
// the unbounded domain map. The Observation Domain ID is a wire field, so one
// permitted source address can name 2^32 domains, and no network-layer
// filter can prevent it.
func TestTemplateStore_DomainsAreBoundedPerExporter(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	const attempts = maxDomainsPerExporter * 4

	for odid := range uint32(attempts) {
		if _, err := d.Decode(testExporter, ipfixHeaderOnly(odid), nil); err != nil {
			t.Fatalf("Decode() error = %v, want the datagram tolerated", err)
		}
	}

	if got := len(d.Domains()); got != maxDomainsPerExporter {
		t.Errorf("domains = %d, want the budget of %d", got, maxDomainsPerExporter)
	}
	if got, want := d.DomainsRefused(), uint64(attempts-maxDomainsPerExporter); got != want {
		t.Errorf("DomainsRefused() = %d, want %d", got, want)
	}
	if got := errorCountFor(d, flow.VersionIPFIX, ReasonDomainLimit); got == 0 {
		t.Error("domain_limit count = 0, want the refusals visible per exporter")
	}
}

// TestTemplateStore_BudgetIsPerExporter pins that one device exhausting its
// budget does not deny another device its own.
func TestTemplateStore_BudgetIsPerExporter(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	other := netip.MustParseAddr("192.0.2.77")

	for odid := range uint32(maxDomainsPerExporter * 2) {
		_, _ = d.Decode(testExporter, ipfixHeaderOnly(odid), nil)
	}
	if _, err := d.Decode(other, ipfixHeaderOnly(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	found := false
	for _, domain := range d.Domains() {
		if domain.Exporter == other {
			found = true
		}
	}
	if !found {
		t.Error("the second exporter got no domain, want budgets kept per device")
	}
}

// TestTemplateStore_DecodingSurvivesTheBudget pins that a device already at
// its budget keeps decoding the domains it established. The refusal must cost
// the new domain alone, never the working ones.
func TestTemplateStore_DecodingSurvivesTheBudget(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()

	// The first domain announces a template and decodes a record.
	if _, err := d.Decode(testExporter,
		ipfixMessage(0, fixtureIPFIXTemplate()), nil); err != nil {
		t.Fatalf("template error = %v, want nil", err)
	}

	// Exhaust the budget with unrelated domains.
	for odid := range uint32(maxDomainsPerExporter * 2) {
		_, _ = d.Decode(testExporter, ipfixHeaderOnly(odid+1000), nil)
	}
	if d.DomainsRefused() == 0 {
		t.Fatal("no domain was refused, the budget did not engage")
	}

	records, err := d.Decode(testExporter,
		ipfixMessage(1, flowSet(fixtureIPFIXTemplateID, fixtureIPFIXRecord())), nil)
	if err != nil {
		t.Fatalf("data error = %v, want nil", err)
	}
	if len(records) != 1 {
		t.Errorf("Decode() returned %d records, want the established domain still decoding", len(records))
	}
}

// TestTemplateStore_SweepReturnsTheBudget pins the whole lifecycle: budget
// exhausted, idle time passes, the sweep frees the slots, and a new domain is
// admitted again.
func TestTemplateStore_SweepReturnsTheBudget(t *testing.T) {
	t.Parallel()

	d := New(config.Parser{MaxFieldsPerTemplate: 128, TemplateTTL: time.Minute})
	now := time.Unix(1_756_600_000, 0)
	d.templates.now = func() time.Time { return now }

	for odid := range uint32(maxDomainsPerExporter) {
		_, _ = d.Decode(testExporter, ipfixHeaderOnly(odid), nil)
	}
	if _, err := d.Decode(testExporter, ipfixHeaderOnly(9999), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if got := d.DomainsRefused(); got != 1 {
		t.Fatalf("DomainsRefused() = %d, want the budget engaged once", got)
	}

	// Nothing has named those domains for longer than the TTL.
	now = now.Add(2 * time.Minute)
	if evicted := d.SweepDomains(); evicted != maxDomainsPerExporter {
		t.Fatalf("SweepDomains() evicted %d, want all %d idle domains", evicted, maxDomainsPerExporter)
	}
	if got := len(d.Domains()); got != 0 {
		t.Fatalf("domains = %d after the sweep, want 0", got)
	}

	// The freed budget admits a new domain.
	if _, err := d.Decode(testExporter, ipfixHeaderOnly(9999), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if got := len(d.Domains()); got != 1 {
		t.Errorf("domains = %d, want the freed slot reused", got)
	}
	if got := d.DomainsRefused(); got != 1 {
		t.Errorf("DomainsRefused() = %d, want no further refusal", got)
	}
}

// TestTemplateStore_SweepSparesLiveDomains pins that the sweep reads the last
// datagram rather than the creation instant.
func TestTemplateStore_SweepSparesLiveDomains(t *testing.T) {
	t.Parallel()

	d := New(config.Parser{MaxFieldsPerTemplate: 128, TemplateTTL: time.Minute})
	now := time.Unix(1_756_600_000, 0)
	d.templates.now = func() time.Time { return now }

	_, _ = d.Decode(testExporter, ipfixHeaderOnly(1), nil)
	_, _ = d.Decode(testExporter, ipfixHeaderOnly(2), nil)

	// Domain 2 keeps speaking while domain 1 falls silent.
	now = now.Add(50 * time.Second)
	_, _ = d.Decode(testExporter, ipfixHeaderOnly(2), nil)

	now = now.Add(30 * time.Second)
	if evicted := d.SweepDomains(); evicted != 1 {
		t.Fatalf("SweepDomains() evicted %d, want only the idle domain", evicted)
	}

	domains := d.Domains()
	if len(domains) != 1 || domains[0].ODID != 2 {
		t.Errorf("domains = %+v, want the live domain kept", domains)
	}
}

// TestInterner_IsBounded pins that the interner stops growing at its bound
// and keeps returning correct values past it, the cost being an allocation
// rather than a wrong reading.
func TestInterner_IsBounded(t *testing.T) {
	t.Parallel()

	i := newInterner()

	for k := range uint32(maxInternedStrings + 1000) {
		// The trailing 0xFF keeps the value distinct and non-empty once
		// trimPadding has taken the export padding off the tail.
		var v [8]byte
		binary.BigEndian.PutUint32(v[0:4], k)
		v[4] = 0xFF

		want := string(v[:5])
		if got := i.intern(v[:]); got != want {
			t.Fatalf("intern() = %q, want %q unchanged past the bound", got, want)
		}
	}

	if got := len(i.m); got != maxInternedStrings {
		t.Errorf("interner holds %d entries, want the bound of %d", got, maxInternedStrings)
	}
}
