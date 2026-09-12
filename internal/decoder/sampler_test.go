package decoder

import (
	"net/netip"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// samplerFixture returns a store holding one sFlow domain, with the clock the
// sampler's idle test reads fixed so a case can move it.
func samplerFixture(t *testing.T) (*templateStore, *domainState, *time.Time) {
	t.Helper()

	at := time.Unix(1_756_300_000, 0)
	s := newTemplateStore(config.Parser{MaxFieldsPerTemplate: 128, TemplateTTL: 30 * time.Minute})
	s.now = func() time.Time { return at }

	d := s.domain(domainKey{
		exporter: netip.MustParseAddr("192.0.2.40"),
		odid:     0,
		proto:    flow.VersionSFlowV5,
	})
	if d == nil {
		t.Fatal("domain() = nil, want a domain")
	}
	return s, d, &at
}

// track calls the tracker the way a datagram does, under the sampler lock the
// decoder holds for the whole sample loop.
func track(s *templateStore, d *domainState, id uint64, seq, rate, pool, drops uint32) {
	d.samplersMu.Lock()
	defer d.samplersMu.Unlock()
	s.trackSamplerLocked(d, id, seq, rate, pool, drops)
}

// TestTrackSampler_AccumulatesOnlyContinuousReadings pins the rule that says
// which pair of readings a difference may be taken between. The agent restarts
// its counters on its own terms, and a difference across one of those is a
// number no sampler measured.
func TestTrackSampler_AccumulatesOnlyContinuousReadings(t *testing.T) {
	t.Parallel()

	const base = 1_000_000

	tests := []struct {
		name      string
		seq       uint32
		rate      uint32
		pool      uint32
		drops     uint32
		wantPool  uint64
		wantDrops uint64
	}{
		{
			name: "the next sample accumulates", seq: 2, rate: 50,
			pool: base + 500, drops: 12, wantPool: 500, wantDrops: 2,
		},
		{
			name: "a sequence past the forward window rebases", seq: (1 << 30) + 1, rate: 50,
			pool: base + 500, drops: 12,
		},
		{
			name: "a sampler reset without a sequence reset rebases", seq: 2, rate: 50,
			pool: 40, drops: 1,
		},
		{
			name: "a rate change rebases", seq: 2, rate: 1000,
			pool: base + 500, drops: 12,
		},
		{
			name: "a counter wrap rebases", seq: 2, rate: 50,
			pool: base + (1 << 30), drops: 12, wantDrops: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s, d, _ := samplerFixture(t)
			track(s, d, 7, 1, 50, base, 10)
			track(s, d, 7, tt.seq, tt.rate, tt.pool, tt.drops)

			if got := d.samplePool.Load(); got != tt.wantPool {
				t.Errorf("sample pool = %d, want %d", got, tt.wantPool)
			}
			if got := d.samplesDropped.Load(); got != tt.wantDrops {
				t.Errorf("samples dropped = %d, want %d", got, tt.wantDrops)
			}
		})
	}
}

// TestTrackSampler_LateSampleLeavesTheBaseWhereItStood pins the one branch
// that must not rebase: a sample the sequence places before the current one
// overtook another, and moving the base back would count its packets twice.
func TestTrackSampler_LateSampleLeavesTheBaseWhereItStood(t *testing.T) {
	t.Parallel()

	s, d, _ := samplerFixture(t)
	track(s, d, 7, 5, 50, 1_000_000, 10)
	track(s, d, 7, 4, 50, 999_600, 8)
	track(s, d, 7, 6, 50, 1_000_500, 12)

	if got := d.samplePool.Load(); got != 500 {
		t.Errorf("sample pool = %d, want 500 measured from the sample that was not overtaken", got)
	}
	if got := d.samplesDropped.Load(); got != 2 {
		t.Errorf("samples dropped = %d, want 2 measured from the same base", got)
	}
}

// TestTrackSampler_RestartBelowTheReorderWindowResumes pins the bound on that
// branch. A sequence restarting from under the window reads exactly like a
// sample that was overtaken, so without a bound the base never moves again.
func TestTrackSampler_RestartBelowTheReorderWindowResumes(t *testing.T) {
	t.Parallel()

	s, d, _ := samplerFixture(t)
	track(s, d, 7, 100, 50, 1_000_000, 10)
	for seq := uint32(1); seq <= 8; seq++ {
		track(s, d, 7, seq, 50, seq*50, 0)
	}

	if got := d.samplePool.Load(); got != 150 {
		t.Errorf("sample pool = %d, want 150 measured once the run ends the base", got)
	}
}

// TestTrackSampler_WireWrapAccumulates pins the width a difference is taken
// at. The counters are uint32 on the wire, so a wrap of their own is a step
// the sampler took rather than a reading it never reported.
func TestTrackSampler_WireWrapAccumulates(t *testing.T) {
	t.Parallel()

	s, d, _ := samplerFixture(t)
	track(s, d, 7, 1, 50, 1<<32-100, 1<<32-6)
	track(s, d, 7, 2, 50, 96, 5)

	if got := d.samplePool.Load(); got != 196 {
		t.Errorf("sample pool = %d, want 196 across the wire's own wrap", got)
	}
	if got := d.samplesDropped.Load(); got != 11 {
		t.Errorf("samples dropped = %d, want 11 across the wire's own wrap", got)
	}
}

// TestTrackSampler_RebaseLeavesTheNextDifferenceMeasurable pins the other half
// of a rebase: the reading it refused to subtract from becomes the base, so
// the sampler resumes rather than staying stuck at its old one.
func TestTrackSampler_RebaseLeavesTheNextDifferenceMeasurable(t *testing.T) {
	t.Parallel()

	s, d, _ := samplerFixture(t)
	track(s, d, 7, 1, 50, 1_000_000, 10)
	track(s, d, 7, 2, 1000, 40, 1) // a rate change rebases
	track(s, d, 7, 3, 1000, 90, 4)

	if got := d.samplePool.Load(); got != 50 {
		t.Errorf("sample pool = %d, want 50 measured from the new base", got)
	}
	if got := d.samplesDropped.Load(); got != 3 {
		t.Errorf("samples dropped = %d, want 3 measured from the new base", got)
	}
}

// TestTrackSampler_BudgetDropsIdleSamplersFirst pins the budget to the rule
// the template store already keeps: a full domain gives up what has gone
// silent before it turns away what is arriving.
func TestTrackSampler_BudgetDropsIdleSamplersFirst(t *testing.T) {
	t.Parallel()

	s, d, at := samplerFixture(t)
	for i := range uint64(maxSamplersPerDomain) {
		track(s, d, i, 1, 50, 100, 0)
	}

	// One more sampler while every seat is held by a live one.
	track(s, d, maxSamplersPerDomain, 1, 50, 100, 0)
	if got := s.refusedSamplers(); got != 1 {
		t.Errorf("refused samplers = %d, want 1 with the budget full", got)
	}
	if got := len(d.samplers); got != maxSamplersPerDomain {
		t.Errorf("samplers held = %d, want the budget %d", got, maxSamplersPerDomain)
	}
	if got := d.samplersOldest; got != at.UnixNano() {
		t.Errorf("oldest sampler = %d, want the fill instant %d", got, at.UnixNano())
	}

	// Past the TTL the seats are free again, and the refusal does not repeat.
	*at = at.Add(time.Hour)
	d.lastSeen.Store(at.UnixNano())
	track(s, d, maxSamplersPerDomain, 1, 50, 100, 0)
	if got := s.refusedSamplers(); got != 1 {
		t.Errorf("refused samplers = %d, want no second refusal once seats freed", got)
	}
	if _, ok := d.samplers[maxSamplersPerDomain]; !ok {
		t.Error("the arriving sampler was not tracked after the idle ones went")
	}
}

// TestTrackSampler_AnAcceptedReadingEndsTheLateRun pins the counter the bound
// is kept on. The run counts samples read as late one after another, so a
// reading taken between two of them has to clear it or the branch retires for
// the rest of the domain's life.
func TestTrackSampler_AnAcceptedReadingEndsTheLateRun(t *testing.T) {
	t.Parallel()

	s, d, _ := samplerFixture(t)
	track(s, d, 7, 100, 50, 1000, 0)
	for seq := uint32(96); seq <= 99; seq++ {
		track(s, d, 7, seq, 50, 900, 0) // fills the run to its bound
	}
	track(s, d, 7, 101, 50, 1050, 0) // accepted, so the run starts over
	track(s, d, 7, 100, 50, 1020, 0) // late again, and still read as late
	track(s, d, 7, 102, 50, 1100, 0)

	if got := d.samplePool.Load(); got != 100 {
		t.Errorf("sample pool = %d, want 100 measured from the base the late run left alone", got)
	}
}

// TestTrackRecordSequence_AnAcceptedMessageEndsTheLateRun pins the reset that
// keeps the guard working. The run bounds how long a base is held against
// messages arriving before it, and a run that never restarts spends its bound
// once and then rewinds on every later overtake.
func TestTrackRecordSequence_AnAcceptedMessageEndsTheLateRun(t *testing.T) {
	t.Parallel()

	d := &domainState{}

	// One datagram to take a position from, then rounds of three: one that
	// skips ahead, the one it overtook arriving late, and one back in order.
	// Each round names the skipped records once and nothing is ever lost.
	const records, rounds = 2, maxLateRun + 2
	base := uint32(100)
	d.trackRecordSequence(base, records, 0, true)

	for range rounds {
		base += records
		d.trackRecordSequence(base+records, records, 0, true) // skips ahead
		d.trackRecordSequence(base, records, 0, true)         // the overtaken one
		base += 2 * records
		d.trackRecordSequence(base, records, 0, true) // back in order
	}

	if got := d.sequenceMissed.Load(); got != rounds*records {
		t.Errorf("SequenceMissed = %d, want %d: the skip counted once per round",
			got, rounds*records)
	}
}

// TestTrackRecordSequence_ARebaseStartsTheLateRunOver pins the state a rebase
// clears. The run belongs to the position it was held against, so carrying it
// past a new engine's base spends the bound early and rebases a message the
// guard should still have held.
func TestTrackRecordSequence_ARebaseStartsTheLateRunOver(t *testing.T) {
	t.Parallel()

	d := &domainState{}

	// One engine skips ahead and its overtaken messages fill the run, then
	// another engine repeats the shape. Each skip names its records once.
	for _, seq := range []uint32{0, 50, 10, 20, 30} {
		d.trackRecordSequence(seq, 10, 0, true)
	}
	for _, seq := range []uint32{900, 880, 890, 910} {
		d.trackRecordSequence(seq, 10, 1, true)
	}

	if got := d.sequenceMissed.Load(); got != 40 {
		t.Errorf("SequenceMissed = %d, want the 40 the first skip named alone", got)
	}
}

// TestTrackRecordSequence_TheWindowBoundsWhatReadsAsLate pins where reordering
// stops and a restart begins. A step back inside the window is a message the
// base already passed, and one beyond it is a device that resumed from a lower
// number, which the counter cannot span.
func TestTrackRecordSequence_TheWindowBoundsWhatReadsAsLate(t *testing.T) {
	t.Parallel()

	const records, base = 10, 10_000

	// A step past the window rebases onto the late message, so the next in
	// order reads the step back less the records that message carried.
	tests := []struct {
		name string
		back uint32
		want uint64
	}{
		{name: "the last position inside the window", back: 1024, want: 0},
		{name: "one past it", back: 1025, want: 1025 - records},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := &domainState{}
			d.trackRecordSequence(base, records, 0, true)
			d.trackRecordSequence(base+records-tt.back, records, 0, true)
			d.trackRecordSequence(base+records, records, 0, true)

			if got := d.sequenceMissed.Load(); got != tt.want {
				t.Errorf("SequenceMissed = %d, want %d", got, tt.want)
			}
		})
	}
}
