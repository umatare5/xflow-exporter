package decoder

import (
	"net/netip"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// sessionsHeld reports how many transport sessions one domain follows.
func sessionsHeld(t *testing.T, d *Decoder, key domainKey) int {
	t.Helper()

	domain := d.templates.domain(key)
	if domain == nil {
		t.Fatalf("domain %v is absent, want it opened", key)
	}
	domain.mu.RLock()
	defer domain.mu.RUnlock()
	return len(domain.sessions)
}

// decodeV9Sequence walks one exchange of template-only datagrams, each from
// the session it names, and returns what the domain made of the sequence.
func decodeV9Sequence(t *testing.T, steps []struct {
	port uint16
	seq  uint32
},
) DomainSnapshot {
	t.Helper()

	d := newTestDecoder()
	for _, step := range steps {
		src := netip.AddrPortFrom(testExporter, step.port)
		if _, err := d.Decode(src, v9Packet(step.seq, fixtureV9ODID, fixtureV9Template()), nil); err != nil {
			t.Fatalf("Decode() error = %v, want nil", err)
		}
	}

	domains := d.Domains()
	if len(domains) != 1 {
		t.Fatalf("Domains() returned %d, want the sessions folded into one", len(domains))
	}
	return domains[0]
}

// The two export processes below are the shape a Catalyst 891 presents: one
// Source ID, two source ports, counters thousands apart. RFC 7011 section 2
// makes the port part of a transport session's identity and the sequence is
// numbered within one, so a single position for the pair reads every
// alternation as a gap the size of the distance between their counters.
func TestDecodeNetFlowV9_NumbersEachTransportSessionApart(t *testing.T) {
	t.Parallel()

	const (
		busy  = 61301
		quiet = 63558
	)
	got := decodeV9Sequence(t, []struct {
		port uint16
		seq  uint32
	}{
		{busy, 6604},
		{busy, 6605},
		{busy, 6606},
		{quiet, 3945},
		{busy, 6607},
		{busy, 6608},
		{quiet, 3946},
		{busy, 6609},
	})

	if got.SequenceMissed != 0 {
		t.Errorf("SequenceMissed = %d, want 0: neither session skipped a packet", got.SequenceMissed)
	}
}

// A gap inside one session is still a gap. Separating the positions must not
// cost the loss detection the counter exists for.
func TestDecodeNetFlowV9_CountsAGapInsideOneSession(t *testing.T) {
	t.Parallel()

	const (
		busy  = 61301
		quiet = 63558
	)
	got := decodeV9Sequence(t, []struct {
		port uint16
		seq  uint32
	}{
		{busy, 6604},
		{quiet, 3945},
		{busy, 6610}, // five packets of the busy session never arrived
		{quiet, 3946},
	})

	if got.SequenceMissed != 5 {
		t.Errorf("SequenceMissed = %d, want the five packets one session skipped", got.SequenceMissed)
	}
}

// A source port is a wire field, so the sessions one domain follows take a
// bound. The datagrams past it decode; only their sequence goes unfollowed,
// which is the cheaper loss -- an established position is worth more than one
// a spoofed port would open.
func TestDecodeNetFlowV9_BoundsTheSessionsOneDomainFollows(t *testing.T) {
	t.Parallel()

	d := newTestDecoder()
	key := domainKey{exporter: testExporter, odid: fixtureV9ODID, proto: flow.VersionNetFlowV9}

	const excess = 4
	for i := range maxSessionsPerDomain + excess {
		src := netip.AddrPortFrom(testExporter, uint16(40000+i))
		records, err := d.Decode(src,
			v9Packet(1, fixtureV9ODID, fixtureV9Template(),
				flowSet(fixtureV9TemplateID, fixtureV9DataRecord())), nil)
		if err != nil {
			t.Fatalf("Decode() from session %d error = %v, want nil", i, err)
		}
		if len(records) != 1 {
			t.Fatalf("Decode() from session %d returned %d records, want the datagram decoded", i, len(records))
		}
	}

	if held := sessionsHeld(t, d, key); held != maxSessionsPerDomain {
		t.Errorf("sessions held = %d, want the bound of %d", held, maxSessionsPerDomain)
	}
}
