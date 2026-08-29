package decoder

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
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

// TestInterner_RefusesUnrepresentableStrings pins the guard on the one label
// value this exporter takes from the wire. A name cut through a multi-byte
// rune by a fixed export width is not valid UTF-8, and Prometheus cannot hold
// it as a label value at all.
func TestInterner_RefusesUnrepresentableStrings(t *testing.T) {
	t.Parallel()

	i := newInterner()

	full := "アプリ"
	truncated := []byte(full)[:8] // cut mid rune, as a fixed-width field does

	if got := i.intern([]byte(full)); got != full {
		t.Errorf("intern() = %q for a whole name, want %q", got, full)
	}
	if got := i.intern(truncated); got != "" {
		t.Errorf("intern() = %q for a truncated name, want it refused", got)
	}
	if got := i.refusedCount(); got != 1 {
		t.Errorf("refusedCount() = %d, want the refusal counted", got)
	}

	// The announced tables take the same path, so a broken options string
	// leaves the table without an entry rather than with a poisoned one.
	tables := newAppTables(i)
	exporter := netip.MustParseAddr("192.0.2.10")
	tables.setName(exporter, 42, truncated)
	tables.setCategory(exporter, 42, truncated)
	if name, category := tables.resolve(exporter, 42); name != "" || category != "" {
		t.Errorf("resolve() = %q, %q; want both absent", name, category)
	}
}

// TestAppTables_RefusedRefreshKeepsLastAnnouncement pins what a refusal does
// to a name the device already announced. An options template repeats one
// device's whole database on every refresh, so a field that arrives
// unrepresentable -- cut mid-rune by the export width, or blanked to nothing
// but padding -- is a damaged export of that same database rather than a
// retraction. Dropping the entry would not leave the dimension absent: the
// application label falls back to the numeric applicationId, which splits one
// application's counters across two series.
func TestAppTables_RefusedRefreshKeepsLastAnnouncement(t *testing.T) {
	t.Parallel()

	tables := newAppTables(newInterner())
	exporter := netip.MustParseAddr("192.0.2.10")

	tables.setName(exporter, 42, []byte("ms-office-365\x00\x00\x00"))
	tables.setCategory(exporter, 42, []byte("business-and-productivity-tools\x00"))

	// The refresh that follows carries one field cut mid rune and one blanked
	// to padding, the two shapes the interner refuses.
	tables.setName(exporter, 42, []byte("アプリ")[:8])
	tables.setCategory(exporter, 42, []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))

	name, category := tables.resolve(exporter, 42)
	if name != "ms-office-365" {
		t.Errorf("resolve() name = %q, want the last good announcement kept", name)
	}
	if category != "business-and-productivity-tools" {
		t.Errorf("resolve() category = %q, want the last good announcement kept", category)
	}
}

// TestInterner_RefusesAnOverlongString pins the other half of the interner's
// budget. The entry bound counts strings and not their bytes, so a device
// exporting a name as wide as its datagram fills the map with datagrams; the
// interner never expires an entry, so what it takes it keeps.
func TestInterner_RefusesAnOverlongString(t *testing.T) {
	t.Parallel()

	i := newInterner()

	atBound := bytes.Repeat([]byte("a"), maxVendorStringLength)
	if got := i.intern(atBound); got != string(atBound) {
		t.Errorf("intern() of a string at the bound = %d bytes, want it kept", len(got))
	}

	overBound := bytes.Repeat([]byte("b"), maxVendorStringLength+1)
	if got := i.intern(overBound); got != "" {
		t.Errorf("intern() of a string past the bound = %d bytes, want it refused", len(got))
	}
	if got := i.refusedCount(); got != 1 {
		t.Errorf("refusedCount() = %d, want the refusal counted", got)
	}

	// Padding is stripped before the length is judged, so a fixed-width
	// export whose name fits is not refused for the width of its field.
	padded := append(bytes.Repeat([]byte("c"), maxVendorStringLength), make([]byte, 64)...)
	if got := i.intern(padded); len(got) != maxVendorStringLength {
		t.Errorf("intern() of a padded string = %d bytes, want %d", len(got), maxVendorStringLength)
	}
}

// TestInterner_IsBounded pins that the interner stops growing at its bound
// and keeps returning correct values past it, the cost being an allocation
// rather than a wrong reading.
func TestInterner_IsBounded(t *testing.T) {
	t.Parallel()

	i := newInterner()

	for k := range maxInternedStrings + 1000 {
		// A distinct name per iteration, in the shape a vendor string comes
		// in: text, padded to a fixed export width with NULs.
		want := "app-" + strconv.Itoa(k)
		v := append([]byte(want), 0, 0, 0)

		if got := i.intern(v); got != want {
			t.Fatalf("intern() = %q, want %q unchanged past the bound", got, want)
		}
	}

	if got := len(i.m); got != maxInternedStrings {
		t.Errorf("interner holds %d entries, want the bound of %d", got, maxInternedStrings)
	}
}

// appTableTemplateID is the options template the application-table fixtures
// announce under.
const appTableTemplateID = 700

// appTableTemplate announces the application name mapping of RFC 6759 6.8:
// applicationId is the scope, and the variable-length name follows it.
func appTableTemplate() []byte {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[0:2], appTableTemplateID)
	binary.BigEndian.PutUint16(body[2:4], 2)
	binary.BigEndian.PutUint16(body[4:6], 1)
	body = append(body, ipfixSpec(fieldApplicationID, 4, 0)...)
	body = append(body, ipfixSpec(fieldApplicationName, variableFieldLength, 0)...)
	return flowSet(ipfixOptionsTemplateSetID, body)
}

// appAnnouncement is one application-table options record.
func appAnnouncement(appID uint32, name string) []byte {
	rec := be32(nil, appID)
	rec = append(rec, byte(len(name)))
	return append(rec, name...)
}

// announceApps declares appIDs 1..count, naming each one distinctly.
func announceApps(t *testing.T, d *Decoder, exporter netip.Addr, count int) {
	t.Helper()

	if _, err := d.Decode(exporter, ipfixMessage(0, appTableTemplate()), nil); err != nil {
		t.Fatalf("options template: %v", err)
	}

	const perMessage = 1024
	for base := 0; base < count; base += perMessage {
		var body []byte
		for k := base; k < base+perMessage && k < count; k++ {
			body = append(body, appAnnouncement(uint32(k)+1, "app-"+strconv.Itoa(k))...)
		}
		if _, err := d.Decode(exporter,
			ipfixMessage(uint32(base)+1, flowSet(appTableTemplateID, body)), nil); err != nil {
			t.Fatalf("announcement at %d: %v", base, err)
		}
	}
}

// TestAppTables_AreBoundedPerExporter is the regression test for the
// unbounded application table. The applicationId is a wire field, so one
// permitted source address can announce 2^32 of them, no network-layer filter
// can prevent it, and nothing expires what the table already holds.
func TestAppTables_AreBoundedPerExporter(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	const attempts = maxAppsPerExporter * 2
	announceApps(t, d, testExporter, attempts)

	table := d.apps.table(testExporter)
	table.mu.RLock()
	held := len(table.names)
	table.mu.RUnlock()

	if held != maxAppsPerExporter {
		t.Errorf("table holds %d applications, want the budget of %d", held, maxAppsPerExporter)
	}
	if got, want := d.ApplicationsRefused(), uint64(attempts-maxAppsPerExporter); got != want {
		t.Errorf("ApplicationsRefused() = %d, want %d", got, want)
	}

	// The applications admitted before the bound keep resolving, and one
	// past it stays numbered rather than being named wrongly.
	if name, _ := d.apps.resolve(testExporter, 1); name != "app-0" {
		t.Errorf("resolve(1) = %q, want the established name kept", name)
	}
	if name, category := d.apps.resolve(testExporter, attempts); name != "" || category != "" {
		t.Errorf("resolve(%d) = %q, %q; want the refused application left absent", attempts, name, category)
	}
}

// TestAppTables_RefreshSurvivesTheBudget pins that a device at its budget
// keeps refreshing the applications it established. The options template
// repeats the whole database periodically, so a bound that refused known
// identifiers would drop nothing but would count forever.
func TestAppTables_RefreshSurvivesTheBudget(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	announceApps(t, d, testExporter, maxAppsPerExporter+10)
	refusedOnce := d.ApplicationsRefused()

	// The device re-announces the same table on its next refresh.
	announceApps(t, d, testExporter, maxAppsPerExporter+10)

	if name, _ := d.apps.resolve(testExporter, maxAppsPerExporter); name == "" {
		t.Error("an established application lost its name on refresh")
	}
	if got, want := d.ApplicationsRefused(), refusedOnce*2; got != want {
		t.Errorf("ApplicationsRefused() = %d, want %d: only the surplus counts again", got, want)
	}
}

// TestAppTables_BudgetIsPerExporter pins that one device exhausting its
// application budget does not deny another device its own.
func TestAppTables_BudgetIsPerExporter(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	other := netip.MustParseAddr("192.0.2.88")

	announceApps(t, d, testExporter, maxAppsPerExporter+1)
	announceApps(t, d, other, 1)

	if name, _ := d.apps.resolve(other, 1); name != "app-0" {
		t.Errorf("resolve() = %q for the second exporter, want budgets kept per device", name)
	}

	// An identifier only the first device announced does not resolve here.
	// One table per device is what makes one budget per device, and the
	// numbering is per protocol pack: two devices on different packs give
	// the same identifier to different applications.
	if name, _ := d.apps.resolve(other, 2); name != "" {
		t.Errorf("resolve(2) = %q for the second exporter, want a table of its own", name)
	}
}

// ipfixVariableLengthTemplate announces template 256 carrying a single
// variable-length field, the encoding only IPFIX has.
func ipfixVariableLengthTemplate(odid uint32) []byte {
	const setLen = 12

	b := be16(nil, 10)
	b = be16(b, ipfixHeaderLen+setLen)
	b = be32(b, 1)
	b = be32(b, 1)
	b = be32(b, odid)

	b = be16(b, 2)
	b = be16(b, setLen)
	b = be16(b, 256)
	b = be16(b, 1)
	b = be16(b, 96)
	return be16(b, variableFieldLength)
}

// v9DataSetNaming builds a v9 data flowset naming one template id, carrying
// four bytes a record of the minimum length would divide into four records.
func v9DataSetNaming(odid uint32, templateID uint16) []byte {
	b := be16(nil, 9)
	b = be16(b, 1)
	b = be32(b, 1000)
	b = be32(b, 1)
	b = be32(b, 1)
	b = be32(b, odid)

	b = be16(b, templateID)
	b = be16(b, flowSetHeaderLen+4)
	return append(b, 0, 0, 0, 0)
}

// v9TemplateNaming announces one v9 template of three four-byte fields:
// source address, destination address and octet count.
func v9TemplateNaming(odid uint32, templateID uint16) []byte {
	body := be16(nil, templateID)
	body = be16(body, 3)
	for _, fieldType := range []uint16{fieldIPv4SrcAddr, fieldIPv4DstAddr, fieldInBytes} {
		body = be16(body, fieldType)
		body = be16(body, 4)
	}

	b := be16(nil, 9)
	b = be16(b, 1)
	b = be32(b, 1000)
	b = be32(b, 1)
	b = be32(b, 1)
	b = be32(b, odid)
	return append(b, flowSet(0, body)...)
}

// v9AddressRecord builds a v9 data flowset of twelve bytes, which the three
// fields above divide into one record.
func v9AddressRecord(odid uint32, setID uint16) []byte {
	rec := []byte{10, 1, 1, 1, 10, 2, 2, 2}
	rec = be32(rec, 4242)

	b := be16(nil, 9)
	b = be16(b, 1)
	b = be32(b, 1000)
	b = be32(b, 1)
	b = be32(b, 1)
	b = be32(b, odid)
	return append(b, flowSet(setID, rec)...)
}

// ipfixSamplingOptionsTemplate announces an IPFIX options template declaring
// one scope field and the sampling interval.
func ipfixSamplingOptionsTemplate(odid uint32, templateID uint16) []byte {
	body := be16(nil, templateID)
	body = be16(body, 2)
	body = be16(body, 1)
	body = be16(body, 144)
	body = be16(body, 4)
	body = be16(body, fieldSamplingInterval)
	body = be16(body, 4)

	set := flowSet(ipfixOptionsTemplateSetID, body)

	b := be16(nil, 10)
	b = be16(b, uint16(ipfixHeaderLen+len(set)))
	b = be32(b, 1)
	b = be32(b, 1)
	b = be32(b, odid)
	return append(b, set...)
}

// TestDecodeV9_DoesNotDecodeAgainstAnotherProtocolsTemplate is the regression
// test for the store merging three protocols into one template id space. A
// device exporting v9 and IPFIX at once sends both from one address, and both
// number templates from 256, so the collision arrives without an attacker.
//
// What made it worse than a lost record is that the walk succeeded: the
// fields agreed on a length, so the bytes reached the aggregator as a
// measurement rather than as an error.
func TestDecodeV9_DoesNotDecodeAgainstAnotherProtocolsTemplate(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	const odid = 7

	if _, err := d.Decode(testExporter, ipfixVariableLengthTemplate(odid), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the IPFIX template accepted", err)
	}

	got, err := d.Decode(testExporter, v9DataSetNaming(odid, 256), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the v9 data set tolerated", err)
	}
	if len(got) != 0 {
		t.Errorf("Decode() returned %d records, want none from a template v9 never announced", len(got))
	}

	if missing := errorCount(d, ReasonMissingTemplate); missing != 1 {
		t.Errorf("missing_template count = %d, want 1 so the gap is visible", missing)
	}
}

// TestDecodeV9_DoesNotPoisonTheSamplingRateFromAnotherProtocol is the severe
// half of the same collision. A v9 data flowset whose id matches an IPFIX
// options template was read as an options record, and whatever its bytes held
// became the domain's sampling rate, which multiplies every count the
// aggregator publishes afterwards.
func TestDecodeV9_DoesNotPoisonTheSamplingRateFromAnotherProtocol(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	const (
		odid       = 7
		optionsID  = 257
		observedID = 300
	)

	if _, err := d.Decode(testExporter, v9TemplateNaming(odid, observedID), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the v9 template accepted", err)
	}
	rateNow := func() uint32 {
		t.Helper()

		got, err := d.Decode(testExporter, v9AddressRecord(odid, observedID), nil)
		if err != nil || len(got) != 1 {
			t.Fatalf("Decode() error = %v, records = %d, want one observable record", err, len(got))
		}
		return got[0].SamplingRate
	}

	before := rateNow()

	if _, err := d.Decode(testExporter, ipfixSamplingOptionsTemplate(odid, optionsID), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the IPFIX options template accepted", err)
	}
	if _, err := d.Decode(testExporter, v9AddressRecord(odid, optionsID), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the colliding v9 data set tolerated", err)
	}

	if after := rateNow(); after != before {
		t.Errorf("sampling rate = %d after a v9 data set, want %d unchanged", after, before)
	}
}

// TestDecodeV9_RefusesAVariableLengthTemplate covers the guard that keeps a
// record walk from reading a field at 65535 bytes. Nothing on the wire
// reaches it now that templates are keyed by protocol, so the template is
// planted in the store directly: the guard prevents a process death, and a
// guard nothing exercises is a guard nobody notices losing.
func TestDecodeV9_RefusesAVariableLengthTemplate(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	const odid = 7

	key := domainKey{exporter: testExporter, odid: odid, proto: flow.VersionNetFlowV9}
	if !d.templates.add(key, 256, &template{
		fields:      []templateField{{fieldType: fieldApplicationName, length: variableFieldLength}},
		recordLen:   1,
		hasVariable: true,
	}) {
		t.Fatal("add() refused the template the test needs")
	}

	got, err := d.Decode(testExporter, v9DataSetNaming(odid, 256), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the v9 data set tolerated", err)
	}
	if len(got) != 0 {
		t.Errorf("Decode() returned %d records, want none from a template v9 cannot walk", len(got))
	}

	if refused := errorCount(d, ReasonInvalidTemplate); refused != 1 {
		t.Errorf("invalid_template count = %d, want 1 so the refusal is visible", refused)
	}
}
