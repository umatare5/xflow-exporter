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
	"github.com/umatare5/xflow-exporter/internal/flow"
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

	ch := make(chan *prometheus.Desc, 20)
	go func() {
		defer close(ch)
		c.Describe(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	if count != 19 {
		t.Errorf("Describe() emitted %d descriptors, want 19", count)
	}
}

func TestDecoderCollector_EmptyUntilTraffic(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(newTestDecoder())

	// Only the refusal counters, which are seeded so a first refusal reads
	// as a rise rather than as a new series. Nothing is published per
	// exporter until a datagram names one.
	if got := testutil.CollectAndCount(c); got != 6 {
		t.Errorf("CollectAndCount() = %d series before any datagram, want only the seeded counters", got)
	}
	for _, name := range []string{
		"xflow_domains_refused_total",
		"xflow_vendor_strings_refused_total",
		"xflow_applications_refused_total",
		"xflow_exporters_refused_total",
		"xflow_sampling_declarations_refused_total",
		"xflow_samplers_refused_total",
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

	if _, err := d.Decode(sentFrom(exporter), buildV5(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if _, err := d.Decode(sentFrom(exporter), []byte{0x00, 0x07, 0x00, 0x00}, nil); err == nil {
		t.Fatal("Decode() error = nil, want an unsupported version rejection")
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_decode_errors_total Decode rejections per exporter, version and reason since process start
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

	// The freshness gauge exists exactly once a record has decoded.
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

// TestDecoderCollector_LeavesATemplatelessDomainUncounted pins the absence a
// v5 or v8 domain keeps. Both open a domain so their export sequence is
// tracked, and neither protocol has a template to hold, so a zero here would
// read as a device that announced none rather than one that cannot.
func TestDecoderCollector_LeavesATemplatelessDomainUncounted(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	if _, err := d.Decode(sentFrom(netip.MustParseAddr("192.0.2.30")), buildV5(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	c := NewDecoderCollector(d)

	if got := testutil.CollectAndCount(c, "xflow_templates"); got != 0 {
		t.Errorf("template series = %d, want none for a protocol without templates", got)
	}
	if got := testutil.CollectAndCount(c, "xflow_sequence_missed_total"); got != 1 {
		t.Errorf("sequence series = %d, want the one v5 domain's", got)
	}
}

func TestDecoderCollector_ReportsDomainState(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.20")

	if _, err := d.Decode(sentFrom(exporter), buildV9TemplateOnly(), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	c := NewDecoderCollector(d)

	expected := `
# HELP xflow_sequence_missed_total Packets on v9 and sFlow, or records on v5, v8 and IPFIX, the sequence numbers say were lost, per domain
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

	if _, err := d.Decode(sentFrom(exporter), v9DomainOnly(1), nil); err != nil {
		t.Fatalf("Decode() error = %v, want the v9 datagram accepted", err)
	}
	if _, err := d.Decode(sentFrom(exporter), sflowDomainOnly(1), nil); err != nil {
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

	records, err := d.Decode(sentFrom(exporter), buildIPFIXRefusedAppName(), nil)
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
# HELP xflow_domains_refused_total Datagrams refused an observation domain since process start, discarded where decoding needs one
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
	domains, strings, applications, exporters, samplers, declarations uint64
	domainList                                                        []decoder.DomainSnapshot
}

func (s stubDecoderSource) Stats() *decoder.Stats               { return &decoder.Stats{} }
func (s stubDecoderSource) Domains() []decoder.DomainSnapshot   { return s.domainList }
func (s stubDecoderSource) DomainsRefused() uint64              { return s.domains }
func (s stubDecoderSource) VendorStringsRefused() uint64        { return s.strings }
func (s stubDecoderSource) ApplicationsRefused() uint64         { return s.applications }
func (s stubDecoderSource) ExportersRefused() uint64            { return s.exporters }
func (s stubDecoderSource) SamplersRefused() uint64             { return s.samplers }
func (s stubDecoderSource) Samplers() []decoder.SamplerSnapshot { return nil }
func (s stubDecoderSource) DeclarationsRefused() uint64         { return s.declarations }

// TestDecoderCollector_RefusalCountersDoNotCross pins each refusal counter to
// its own accessor. The three publish lines are adjacent and alike, and the
// causes they report are not: a domain budget, an export field too narrow for
// its string, an application budget and an exporter budget each call for a
// different answer.
func TestDecoderCollector_RefusalCountersDoNotCross(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(stubDecoderSource{
		domains: 3, strings: 5, applications: 7, exporters: 11, samplers: 13, declarations: 17,
	})

	expected := `
# HELP xflow_domains_refused_total Datagrams refused an observation domain since process start, discarded where decoding needs one
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
# HELP xflow_samplers_refused_total Flow samples left untracked since process start, their domain being at its sampler budget
# TYPE xflow_samplers_refused_total counter
xflow_samplers_refused_total 13
# HELP xflow_sampling_declarations_refused_total Sampling declarations discarded since process start, the exporter being at its sampler budget
# TYPE xflow_sampling_declarations_refused_total counter
xflow_sampling_declarations_refused_total 17
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_domains_refused_total", "xflow_vendor_strings_refused_total",
		"xflow_applications_refused_total", "xflow_exporters_refused_total",
		"xflow_samplers_refused_total", "xflow_sampling_declarations_refused_total"); err != nil {
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

// TestDecoderCollector_SeparatesFlowFromDatagram pins the two instants apart.
// A datagram that decodes into no record still reaches the device, and an
// sFlow agent polling counters alone sends those forever, so holding the flow
// instant forward on one would leave a stopped sampler reading as fresh.
func TestDecoderCollector_SeparatesFlowFromDatagram(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.21")

	records, err := d.Decode(sentFrom(exporter), buildV9TemplateOnly(), nil)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if len(records) != 0 {
		t.Fatalf("Decode() = %d records, want 0 from a template-only datagram", len(records))
	}

	c := NewDecoderCollector(d)
	if got := testutil.CollectAndCount(c, "xflow_last_flow_timestamp_seconds"); got != 0 {
		t.Errorf("last flow timestamp series = %d, want 0 until a record decodes", got)
	}
	if got := testutil.CollectAndCount(c, "xflow_last_datagram_timestamp_seconds"); got != 1 {
		t.Errorf("last datagram timestamp series = %d, want 1", got)
	}
}

// buildSFlowFlowSample crafts an sFlow datagram carrying one flow sample with
// no flow record, which is all the sampler counters need: they ride the sample
// header rather than the records under it.
func buildSFlowFlowSample(datagramSeq, sampleSeq, pool, drops uint32) []byte {
	p := make([]byte, 0, 68)
	word := func(v uint32) { p = binary.BigEndian.AppendUint32(p, v) }

	word(5)                      // version
	word(1)                      // agent address type IPv4
	p = append(p, 192, 0, 2, 30) // agent address
	word(0)                      // sub-agent id
	word(datagramSeq)            // datagram sequence
	word(1000)                   // uptime
	word(1)                      // one sample

	word(1)  // flow sample
	word(32) // sample length
	word(sampleSeq)
	word(0x01_000003) // source id: type 1, index 3
	word(50)          // sampling rate
	word(pool)
	word(drops)
	word(3) // input interface
	word(4) // output interface
	word(0) // no flow records
	return p
}

// TestDecoderCollector_SamplerCountersNeedTwoReadings pins the pair to a
// measured difference. One reading is a base with nothing to subtract from,
// and publishing its zero would divide a corrected packet count by nothing.
func TestDecoderCollector_SamplerCountersNeedTwoReadings(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.30")
	c := NewDecoderCollector(d)

	if _, err := d.Decode(sentFrom(exporter), buildSFlowFlowSample(1, 1, 5000, 7), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if got := testutil.CollectAndCount(c, "xflow_sample_pool_packets_total"); got != 0 {
		t.Errorf("sample pool series = %d, want 0 after one reading", got)
	}

	if _, err := d.Decode(sentFrom(exporter), buildSFlowFlowSample(2, 2, 5500, 9), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	expected := `
# HELP xflow_sample_pool_packets_total Packets the sFlow samplers of one domain could have sampled, sFlow only
# TYPE xflow_sample_pool_packets_total counter
xflow_sample_pool_packets_total{exporter_address="192.0.2.30",odid="0",version="sflow_v5"} 500
# HELP xflow_samples_dropped_total Flow samples the sFlow agent of one domain could not send, sFlow only
# TYPE xflow_samples_dropped_total counter
xflow_samples_dropped_total{exporter_address="192.0.2.30",odid="0",version="sflow_v5"} 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"xflow_sample_pool_packets_total", "xflow_samples_dropped_total"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}

	// An sFlow domain holds no template, so the gauge that counts them is
	// absent there rather than reporting a zero of something that cannot be.
	if got := testutil.CollectAndCount(c, "xflow_templates"); got != 0 {
		t.Errorf("templates series = %d, want 0 for an sFlow domain", got)
	}
}

// TestDecoderCollector_ARefusedDifferenceLeavesItsCounterAbsent pins the pair
// to one gate each. A drop count the domain refused as a restart leaves a
// zero, and publishing it beside a measured pool would read as no loss.
func TestDecoderCollector_ARefusedDifferenceLeavesItsCounterAbsent(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.30")
	c := NewDecoderCollector(d)

	// The pool steps by 500 while the drop counter steps past the window the
	// tracker reads as one agent's continuous run.
	if _, err := d.Decode(sentFrom(exporter), buildSFlowFlowSample(1, 1, 5000, 0), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
	if _, err := d.Decode(sentFrom(exporter), buildSFlowFlowSample(2, 2, 5500, 1<<31), nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if got := testutil.CollectAndCount(c, "xflow_sample_pool_packets_total"); got != 1 {
		t.Errorf("sample pool series = %d, want 1 measured", got)
	}
	if got := testutil.CollectAndCount(c, "xflow_samples_dropped_total"); got != 0 {
		t.Errorf("samples dropped series = %d, want 0 with its difference refused", got)
	}

	// The same pair the other way round, on a device of its own.
	other := netip.MustParseAddr("192.0.2.31")
	for _, pool := range []uint32{5000, 5000 + 1<<31} {
		if _, err := d.Decode(sentFrom(other), buildSFlowFlowSample(1, 1, pool, 0), nil); err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
	}

	if got := testutil.CollectAndCount(c, "xflow_sample_pool_packets_total"); got != 1 {
		t.Errorf("sample pool series = %d, want 1 with the second device's difference refused", got)
	}
}

// buildV9SamplerTable crafts a v9 datagram announcing a system-scoped sampler
// table and one entry in it, which is the shape a Catalyst exports.
func buildV9SamplerTable(sequence, samplerID, rate byte) []byte {
	return []byte{
		0x00, 0x09, 0x00, 0x02, // version 9, count 2
		0x00, 0x00, 0x00, 0x00, // sysUptime
		0x68, 0x00, 0x00, 0x00, // unix_secs
		0x00, 0x00, 0x00, sequence,
		0x00, 0x00, 0x01, 0x00, // source id 256
		// options template flowset: id 1, length 22, template 500
		0x00, 0x01, 0x00, 0x16,
		0x01, 0xF4, 0x00, 0x04, 0x00, 0x08, // id 500, scope 4 bytes, options 8
		0x00, 0x01, 0x00, 0x04, // scope: system(4)
		0x00, 0x30, 0x00, 0x04, // samplerId(4)
		0x00, 0x32, 0x00, 0x04, // samplerRandomInterval(4)
		// data flowset for template 500, length 16
		0x01, 0xF4, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x09, // scope value
		0x00, 0x00, 0x00, samplerID,
		0x00, 0x00, 0x00, rate,
	}
}

// TestDecoderCollector_ADomainOfSeveralSamplersAuditsThemIndividually pins the
// two rate families apart. A domain declaring several has no single rate in
// force, so its own series is absent -- and the corrections still applied
// would have nothing to read them by without the per-sampler one.
func TestDecoderCollector_ADomainOfSeveralSamplersAuditsThemIndividually(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	exporter := netip.MustParseAddr("192.0.2.21")
	for i, entry := range [][2]byte{{1, 32}, {2, 64}} {
		if _, err := d.Decode(sentFrom(exporter), buildV9SamplerTable(byte(i+1), entry[0], entry[1]), nil); err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
	}

	c := NewDecoderCollector(d)
	expected := `
# HELP xflow_sampler_rate Packet sampling rate a device declared for one named sampler
# TYPE xflow_sampler_rate gauge
xflow_sampler_rate{exporter_address="192.0.2.21",odid="256",sampler="1",version="netflow_v9"} 32
xflow_sampler_rate{exporter_address="192.0.2.21",odid="256",sampler="2",version="netflow_v9"} 64
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "xflow_sampler_rate"); err != nil {
		t.Errorf("CollectAndCompare() mismatch: %v", err)
	}
	if got := testutil.CollectAndCount(c, "xflow_sampling_rate"); got != 0 {
		t.Errorf("xflow_sampling_rate = %d series, want none with no single rate in force", got)
	}
}

// TestDecoderCollector_CorrectionAuditRidesTheSamplingDevicesAlone pins the
// gate on the audit counters. A device that never declared is not sampling, so a zero
// on it would copy xflow_flows_total across the fleet and read as a fault
// where there is none.
func TestDecoderCollector_CorrectionAuditRidesTheSamplingDevicesAlone(t *testing.T) {
	t.Parallel()

	c := NewDecoderCollector(stubDecoderSource{domainList: []decoder.DomainSnapshot{
		{
			Exporter: netip.MustParseAddr("192.0.2.1"), ODID: 1,
			Version: flow.VersionNetFlowV9, SamplingUnresolved: 3, SamplerRateChanges: 2, Sampled: true,
		},
		{
			Exporter: netip.MustParseAddr("192.0.2.2"), ODID: 2,
			Version: flow.VersionNetFlowV9, SamplingUnresolved: 7, SamplerRateChanges: 4, Sampled: false,
		},
		{
			// v5 declares no rate anywhere, so its records reach the end of
			// the precedence by construction. The series is the only place
			// that shows it.
			Exporter: netip.MustParseAddr("192.0.2.3"), ODID: 0,
			Version: flow.VersionNetFlowV5, SamplingUnresolved: 5, Sampled: true,
		},
		{
			Exporter: netip.MustParseAddr("192.0.2.4"), ODID: 0,
			Version: flow.VersionNetFlowV8, SamplingUnresolved: 9, Sampled: true,
		},
	}})

	const want = `# HELP xflow_sampling_unresolved_flows_total Records no declaration settled a sampling rate for, taken uncorrected, per domain
# TYPE xflow_sampling_unresolved_flows_total counter
xflow_sampling_unresolved_flows_total{exporter_address="192.0.2.1",odid="1",version="netflow_v9"} 3
xflow_sampling_unresolved_flows_total{exporter_address="192.0.2.3",odid="0",version="netflow_v5"} 5
# HELP xflow_sampler_rate_changes_total Declarations that gave a sampler a rate differing from the one the domain held for it
# TYPE xflow_sampler_rate_changes_total counter
xflow_sampler_rate_changes_total{exporter_address="192.0.2.1",odid="1",version="netflow_v9"} 2
xflow_sampler_rate_changes_total{exporter_address="192.0.2.3",odid="0",version="netflow_v5"} 0
`

	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"xflow_sampling_unresolved_flows_total", "xflow_sampler_rate_changes_total"); err != nil {
		t.Errorf("CollectAndCompare() error = %v", err)
	}
}

// sentFrom is the transport session a fixture datagram arrives on. One export
// process is all these tests need, the session split being the decoder's.
func sentFrom(addr netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(addr, 50000)
}
