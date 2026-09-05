package enrich

import (
	"net/netip"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

func serviceRecord(protocol uint8, srcPort, dstPort uint16) flow.Record {
	return flow.Record{
		Exporter: netip.MustParseAddr("192.0.2.1"),
		SrcAddr:  netip.MustParseAddr("10.0.0.1"),
		DstAddr:  netip.MustParseAddr("10.0.0.2"),
		Protocol: protocol,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}
}

func TestServices_NamesFromTheDestinationPort(t *testing.T) {
	t.Parallel()

	s := NewServices()
	r := serviceRecord(protocolTCP, 51234, 443)
	s.Enrich(&r)

	if r.AppName != "https" {
		t.Errorf("AppName = %q, want https from the destination port", r.AppName)
	}
	if got := s.Snapshot(); got.Filled != 1 || got.Unknown != 0 || got.Skipped != 0 {
		t.Errorf("Snapshot() = %+v, want one filled", got)
	}
}

// TestServices_NamesFromTheSourcePort covers the return direction, where the
// device exported the service side as the source.
func TestServices_NamesFromTheSourcePort(t *testing.T) {
	t.Parallel()

	s := NewServices()
	r := serviceRecord(protocolTCP, 22, 51234)
	s.Enrich(&r)

	if r.AppName != "ssh" {
		t.Errorf("AppName = %q, want ssh from the source port", r.AppName)
	}
}

// TestServices_DestinationWinsOverSource pins the precedence when both ports
// name a service.
func TestServices_DestinationWinsOverSource(t *testing.T) {
	t.Parallel()

	s := NewServices()
	r := serviceRecord(protocolTCP, 22, 443)
	s.Enrich(&r)

	if r.AppName != "https" {
		t.Errorf("AppName = %q, want the destination port to win", r.AppName)
	}
}

// TestServices_DeviceReadingWins is the rule the whole package rests on: the
// device saw the packet and this exporter did not.
func TestServices_DeviceReadingWins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		record  flow.Record
		wantApp string
	}{
		{
			name: "an exported name is untouched",
			record: func() flow.Record {
				r := serviceRecord(protocolTCP, 51234, 443)
				r.AppName = "ms-office-365"
				return r
			}(),
			wantApp: "ms-office-365",
		},
		{
			name: "an exported identifier is untouched even without a name",
			record: func() flow.Record {
				r := serviceRecord(protocolTCP, 51234, 443)
				r.AppID = 13<<24 | 42
				return r
			}(),
			wantApp: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewServices()
			r := tt.record
			s.Enrich(&r)

			if r.AppName != tt.wantApp {
				t.Errorf("AppName = %q, want %q", r.AppName, tt.wantApp)
			}
			if got := s.Snapshot(); got.Skipped != 1 || got.Filled != 0 {
				t.Errorf("Snapshot() = %+v, want one skipped", got)
			}
		})
	}
}

// TestServices_UnknownPortsNameNothing pins that an ephemeral pair keeps no
// name: a guess would be a reading nobody made.
func TestServices_UnknownPortsNameNothing(t *testing.T) {
	t.Parallel()

	s := NewServices()
	r := serviceRecord(protocolTCP, 51234, 49152)
	s.Enrich(&r)

	if r.AppName != "" {
		t.Errorf("AppName = %q, want it absent", r.AppName)
	}
	if got := s.Snapshot(); got.Unknown != 1 {
		t.Errorf("Snapshot() = %+v, want one unknown", got)
	}
}

// TestServices_ProtocolIsPartOfTheKey pins that a UDP-only assignment does
// not name a TCP flow on the same number.
func TestServices_ProtocolIsPartOfTheKey(t *testing.T) {
	t.Parallel()

	s := NewServices()

	udp := serviceRecord(protocolUDP, 40000, 500)
	s.Enrich(&udp)
	if udp.AppName != "isakmp" {
		t.Errorf("UDP 500 named %q, want isakmp", udp.AppName)
	}

	tcp := serviceRecord(protocolTCP, 40000, 500)
	s.Enrich(&tcp)
	if tcp.AppName != "" {
		t.Errorf("TCP 500 named %q, want nothing", tcp.AppName)
	}
}

func TestChain_AppliesToEveryRecord(t *testing.T) {
	t.Parallel()

	chain := NewChain(NewServices())
	if !chain.Enabled() {
		t.Fatal("Enabled() = false with one enricher, want true")
	}

	records := []flow.Record{
		serviceRecord(protocolTCP, 51234, 443),
		serviceRecord(protocolUDP, 40000, 53),
	}
	chain.Enrich(records)

	if records[0].AppName != "https" || records[1].AppName != "dns" {
		t.Errorf("records = %+v, want both named", records)
	}

	snaps := chain.Snapshot()
	if len(snaps) != 1 || snaps[0].Enricher != "services" || snaps[0].Filled != 2 {
		t.Errorf("Snapshot() = %+v, want two filled by services", snaps)
	}
}

// TestChain_EmptyIsANoOp pins that the ingest path needs no nil check.
func TestChain_EmptyIsANoOp(t *testing.T) {
	t.Parallel()

	var nilChain *Chain
	if nilChain.Enabled() {
		t.Error("Enabled() = true on a nil chain, want false")
	}
	nilChain.Enrich([]flow.Record{serviceRecord(protocolTCP, 1, 443)})
	nilChain.Close()
	if got := nilChain.Snapshot(); got != nil {
		t.Errorf("Snapshot() = %+v on a nil chain, want nil", got)
	}

	empty := NewChain()
	if empty.Enabled() {
		t.Error("Enabled() = true on an empty chain, want false")
	}

	records := []flow.Record{serviceRecord(protocolTCP, 51234, 443)}
	empty.Enrich(records)
	if records[0].AppName != "" {
		t.Errorf("an empty chain named %q, want it to do nothing", records[0].AppName)
	}
}

// TestServices_NamesTheCurrentTable covers what the table gained or
// re-pointed: 443 and 853 carry a different protocol on each transport, and
// the tunnels exist on UDP alone.
func TestServices_NamesTheCurrentTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol uint8
		port     uint16
		want     string
	}{
		{name: "tls over tcp 443", protocol: protocolTCP, port: 443, want: "https"},
		{name: "quic over udp 443", protocol: protocolUDP, port: 443, want: "http3"},
		{name: "dot over tcp 853", protocol: protocolTCP, port: 853, want: "dns-over-tls"},
		{name: "doq over udp 853", protocol: protocolUDP, port: 853, want: "dns-over-quic"},
		{name: "radsec over tcp", protocol: protocolTCP, port: 2083, want: "radsec"},
		{name: "vxlan over udp", protocol: protocolUDP, port: 4789, want: "vxlan"},
		{name: "vxlan not over tcp", protocol: protocolTCP, port: 4789, want: ""},
		{name: "kerberos over either", protocol: protocolUDP, port: 88, want: "kerberos"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewServices()
			r := serviceRecord(tt.protocol, 51234, tt.port)
			s.Enrich(&r)

			if r.AppName != tt.want {
				t.Errorf("AppName = %q, want %q", r.AppName, tt.want)
			}
		})
	}
}

// TestServices_RetiredNumbersNameNothing keeps the numbers the table dropped
// from growing back. A name that outlives the service it points at reads as
// a measurement rather than as the stale guess it is.
func TestServices_RetiredNumbersNameNothing(t *testing.T) {
	t.Parallel()

	ports := []uint16{
		20, 110, 119, 515, 520, 1194, 1723, 5900, 11211,
		3000, 3100, 4317, 4318, 6443, 9090, 9092, 9100, 9115, 9116, 9200, 51820,
	}

	for _, protocol := range []uint8{protocolTCP, protocolUDP} {
		for _, port := range ports {
			s := NewServices()
			r := serviceRecord(protocol, 51234, port)
			s.Enrich(&r)

			if r.AppName != "" {
				t.Errorf("port %d/%d named %q, want nothing", port, protocol, r.AppName)
			}
		}
	}
}

// TestServiceNames_StaysWithinItsCeiling holds the table to its bound. The 48
// registrations expand to this many entries, a shared number holding two.
func TestServiceNames_StaysWithinItsCeiling(t *testing.T) {
	t.Parallel()

	const ceiling = 86

	if got := len(serviceNames); got > ceiling {
		t.Errorf("serviceNames holds %d entries, want at most %d", got, ceiling)
	}
}

func BenchmarkServices_Enrich(b *testing.B) {
	s := NewServices()
	r := serviceRecord(protocolTCP, 51234, 443)

	b.ReportAllocs()
	for b.Loop() {
		r.AppName = ""
		s.Enrich(&r)
	}
}
