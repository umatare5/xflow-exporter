package collector

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
)

// newTestDecoder builds a decoder with the default parser limits.
func newTestDecoder() *decoder.Decoder {
	return decoder.New(config.Parser{
		MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
		TemplateTTL:          config.DefaultParserTemplateTTL,
	})
}

// buildV5 crafts a minimal one-record NetFlow v5 datagram for driving the
// decoder the collector under test reads.
func buildV5() []byte {
	payload := make([]byte, 24+48)
	payload[1] = 5  // version
	payload[3] = 1  // count
	payload[9] = 1  // unix_secs, any non-zero epoch
	payload[62] = 6 // protocol
	return payload
}

func TestDecoderCollector_Describe(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(newTestDecoder())

	ch := make(chan *prometheus.Desc, 16)
	go func() {
		defer close(ch)
		c.Describe(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	if count != 10 {
		t.Errorf("Describe() emitted %d descriptors, want 10", count)
	}
}

func TestDecoderCollector_EmptyUntilTraffic(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(newTestDecoder())

	// Only the refusal counters, which are seeded so a first refusal reads
	// as a rise rather than as a new series. Nothing is published per
	// exporter until a datagram names one.
	if got := testutil.CollectAndCount(c); got != 4 {
		t.Errorf("CollectAndCount() = %d series before any datagram, want only the seeded counters", got)
	}
	for _, name := range []string{
		"xflow_domains_refused_total",
		"xflow_vendor_strings_refused_total",
		"xflow_applications_refused_total",
		"xflow_exporters_refused_total",
	} {
		if got := testutil.CollectAndCount(c, name); got != 1 {
			t.Errorf("%s series = %d, want 1 seeded", name, got)
		}
	}
}

func TestDecoderCollector_ReportsOutcomes(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.10")

	if _, err := d.Decode(exporter, buildV5(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if _, err := d.Decode(exporter, []byte{0x00, 0x07, 0x00, 0x00}, nil); err == nil {
		t.Fatal("Decode() error = nil, want an unsupported version rejection")
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_decode_errors_total Datagrams rejected per exporter, version and reason since process start
# TYPE xflow_decode_errors_total counter
xflow_decode_errors_total{exporter_address="192.0.2.10",reason="unsupported_version",version="unknown"} 1
# HELP xflow_flows_total Flow records decoded per exporter and version since process start
# TYPE xflow_flows_total counter
xflow_flows_total{exporter_address="192.0.2.10",version="netflow_v5"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_flows_total", "xflow_decode_errors_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}

	// The freshness gauge exists exactly once a decode has succeeded.
	if got := testutil.CollectAndCount(c, "xflow_last_flow_timestamp_seconds"); got != 1 {
		t.Errorf("last flow timestamp series = %d, want 1", got)
	}
}

// buildV9TemplateOnly crafts a v9 datagram announcing one two-field template
// so the domain series gain a subject.
func buildV9TemplateOnly() []byte {
	return []byte{
		0x00, 0x09, 0x00, 0x01, // version 9, count 1
		0x00, 0x00, 0x00, 0x00, // sysUptime
		0x68, 0x00, 0x00, 0x00, // unix_secs
		0x00, 0x00, 0x00, 0x05, // sequence 5
		0x00, 0x00, 0x01, 0x00, // source id 256
		// template flowset: id 0, length 16, template 300 with two fields
		0x00, 0x00, 0x00, 0x10,
		0x01, 0x2C, 0x00, 0x02,
		0x00, 0x01, 0x00, 0x04, // IN_BYTES(4)
		0x00, 0x02, 0x00, 0x04, // IN_PKTS(4)
	}
}

func TestDecoderCollector_ReportsDomainState(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.20")

	if _, err := d.Decode(exporter, buildV9TemplateOnly(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_sequence_missed_total Export packets the sequence numbers say were lost, per protocol and observation domain
# TYPE xflow_sequence_missed_total counter
xflow_sequence_missed_total{exporter_address="192.0.2.20",odid="256",version="netflow_v9"} 0
# HELP xflow_templates Unexpired templates held per exporter, protocol, observation domain and kind
# TYPE xflow_templates gauge
xflow_templates{exporter_address="192.0.2.20",odid="256",type="options_template",version="netflow_v9"} 0
xflow_templates{exporter_address="192.0.2.20",odid="256",type="template",version="netflow_v9"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_templates", "xflow_sequence_missed_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}

	// No options arrived, so no sampling rate series exists.
	if got := testutil.CollectAndCount(c, "xflow_sampling_rate"); got != 0 {
		t.Errorf("sampling rate series = %d, want 0 until a rate arrives", got)
	}
}

// v9DomainOnly is a v9 header naming an observation domain and carrying no
// flowset, which is enough to open the domain.
func v9DomainOnly(odid uint32) []byte {
	b := []byte{0x00, 0x09, 0x00, 0x00}
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, 1)
	return binary.BigEndian.AppendUint32(b, odid)
}

// sflowDomainOnly is an sFlow v5 datagram naming a sub-agent and carrying no
// sample, which is likewise enough to open a domain.
func sflowDomainOnly(subAgent uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, 5)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, 192, 0, 2, 20)
	b = binary.BigEndian.AppendUint32(b, subAgent)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, 1000)
	return binary.BigEndian.AppendUint32(b, 0)
}

// TestDecoderCollector_TwoProtocolsUnderOneIdentifierStillGather is the
// regression test for a scrape that returned 500 for every series in the
// registry. The template store keys domains by protocol, which two datagrams
// naming the same number open separately, and the domain series carried only
// the exporter and the identifier -- so the registry saw one label set twice
// and refused to gather anything at all, this exporter's own health series
// included. A device speaking v9 with Source ID 0 and sFlow from sub-agent 0
// reaches it on defaults.
func TestDecoderCollector_TwoProtocolsUnderOneIdentifierStillGather(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.20")

	if _, err := d.Decode(exporter, v9DomainOnly(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the v9 datagram accepted", err)
	}
	if _, err := d.Decode(exporter, sflowDomainOnly(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the sFlow datagram accepted", err)
	}
	if got := len(d.Domains()); got != 2 {
		t.Fatalf("Domains() = %d, want 2 so the collision is under test", got)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewDecoderCollector(d))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want every series to gather", err)
	}
	if len(families) == 0 {
		t.Fatal("Gather() returned no families")
	}
}

// buildIPFIXRefusedAppName crafts one IPFIX message carrying the same
// mid-rune-truncated application name down both string paths: the table an
// options record announces, and the name a data record embeds inline. The
// value is []byte("アプリ")[:8], what a fixed-width export field produces.
func buildIPFIXRefusedAppName() []byte {
	return []byte{
		0x00, 0x0A, 0x00, 0x5C, // version 10, message length 92
		0x68, 0x00, 0x00, 0x00, // export time
		0x00, 0x00, 0x00, 0x00, // sequence
		0x00, 0x00, 0x02, 0x00, // observation domain 512

		// options template 600: applicationId as scope, then the identifier
		// and name pair the application table is built from
		0x00, 0x03, 0x00, 0x16,
		0x02, 0x58, 0x00, 0x03, 0x00, 0x01,
		0x00, 0x5F, 0x00, 0x04, // applicationId, scope
		0x00, 0x5F, 0x00, 0x04, // applicationId
		0x00, 0x60, 0xFF, 0xFF, // applicationName, variable length

		// options record announcing the unrepresentable name
		0x02, 0x58, 0x00, 0x15,
		0x0D, 0x00, 0x00, 0x2A,
		0x0D, 0x00, 0x00, 0x2A,
		0x08, 0xE3, 0x82, 0xA2, 0xE3, 0x83, 0x97, 0xE3, 0x83,

		// data template 400: byte count and an inline application name
		0x00, 0x02, 0x00, 0x10,
		0x01, 0x90, 0x00, 0x02,
		0x00, 0x01, 0x00, 0x04, // IN_BYTES(4)
		0x00, 0x60, 0xFF, 0xFF, // applicationName, variable length

		// data record carrying the same unrepresentable name inline
		0x01, 0x90, 0x00, 0x11,
		0x00, 0x00, 0x00, 0x64,
		0x08, 0xE3, 0x82, 0xA2, 0xE3, 0x83, 0x97, 0xE3, 0x83,
	}
}

// TestDecoderCollector_ReportsRefusedVendorStrings drives a real decoder down
// both paths a vendor string reaches the interner by, and pins that each
// refusal lands on its own published counter rather than on the sibling's.
func TestDecoderCollector_ReportsRefusedVendorStrings(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.30")

	records, err := d.Decode(exporter, buildIPFIXRefusedAppName(), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want the message tolerated", err)
	}
	if len(records) != 1 {
		t.Fatalf("Decode() returned %d records, want 1", len(records))
	}
	if records[0].AppName != "" {
		t.Errorf("AppName = %q, want the dimension left absent", records[0].AppName)
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_domains_refused_total Datagrams discarded since process start, the exporter being at its observation domain budget
# TYPE xflow_domains_refused_total counter
xflow_domains_refused_total 0
# HELP xflow_vendor_strings_refused_total Vendor string fields refused since process start, counted per occurrence rather than per string
# TYPE xflow_vendor_strings_refused_total counter
xflow_vendor_strings_refused_total 2
# HELP xflow_applications_refused_total Application announcements refused since process start, the exporter being at its application budget
# TYPE xflow_applications_refused_total counter
xflow_applications_refused_total 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_vendor_strings_refused_total", "xflow_domains_refused_total",
		"xflow_applications_refused_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

// stubDecoderSource reports a distinct count from each refusal accessor.
type stubDecoderSource struct {
	domains, strings, applications, exporters uint64
}

func (s stubDecoderSource) Stats() *decoder.Stats             { return &decoder.Stats{} }
func (s stubDecoderSource) Domains() []decoder.DomainSnapshot { return nil }
func (s stubDecoderSource) DomainsRefused() uint64            { return s.domains }
func (s stubDecoderSource) VendorStringsRefused() uint64      { return s.strings }
func (s stubDecoderSource) ApplicationsRefused() uint64       { return s.applications }
func (s stubDecoderSource) ExportersRefused() uint64          { return s.exporters }

// TestDecoderCollector_RefusalCountersDoNotCross pins each refusal counter to
// its own accessor. The three publish lines are adjacent and alike, and the
// causes they report are not: a domain budget, an export field too narrow for
// its string, an application budget and an exporter budget each call for a
// different answer.
func TestDecoderCollector_RefusalCountersDoNotCross(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(stubDecoderSource{domains: 3, strings: 5, applications: 7, exporters: 11})

	expected := `
# HELP xflow_domains_refused_total Datagrams discarded since process start, the exporter being at its observation domain budget
# TYPE xflow_domains_refused_total counter
xflow_domains_refused_total 3
# HELP xflow_vendor_strings_refused_total Vendor string fields refused since process start, counted per occurrence rather than per string
# TYPE xflow_vendor_strings_refused_total counter
xflow_vendor_strings_refused_total 5
# HELP xflow_applications_refused_total Application announcements refused since process start, the exporter being at its application budget
# TYPE xflow_applications_refused_total counter
xflow_applications_refused_total 7
# HELP xflow_exporters_refused_total Datagrams left unattributed since process start, the process being at its exporter budget
# TYPE xflow_exporters_refused_total counter
xflow_exporters_refused_total 11
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_domains_refused_total", "xflow_vendor_strings_refused_total",
		"xflow_applications_refused_total", "xflow_exporters_refused_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
}

func TestCollector_RegisterDecoderCollector(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterDecoderCollector(newTestDecoder())

	// The registry accepts the collector; series appear with traffic.
	if _, err := c.Registry().Gather(); err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
}
