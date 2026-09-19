// This file holds the template store NetFlow v9 and IPFIX decoding depends
// on, and the per-domain state that travels with it.

package decoder

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/flow"
)

// maxTemplatesPerDomain bounds one observation domain against a device, or an
// attacker, registering templates without end. Real devices carry tens.
const maxTemplatesPerDomain = 8192

// maxSamplersPerDomain bounds the samplers one observation domain tracks. A
// source id is a wire field, so the map it keys grows with what a sender
// chooses rather than with the ports a device holds.
const maxSamplersPerDomain = 4096

// maxLateRun bounds a run of samples one sampler's sequence places before the
// current position. Reordering runs a datagram or two deep, so a longer run is
// an agent that restarted from a sequence low enough to read as reordering,
// and holding the base still for it freezes the counters for good.
const maxLateRun = 4

// maxDomainsPerExporter bounds the observation domains one device may open.
// The Observation Domain ID is a wire field rather than a property of the
// fleet, so a device with a broken numbering scheme, or one under an
// attacker's control, would otherwise mint domains without end from a single
// permitted source address. A chassis exports one per linecard or VRF, so
// hundreds is already generous.
const maxDomainsPerExporter = 256

// maxSessionsPerDomain bounds the transport sessions one domain follows. A
// source port is a wire field, so a sender varying it would otherwise mint
// positions without end. A device runs one export process per port and a
// handful of processes at most, so the bound is an order of magnitude above
// what one has been seen to open.
const maxSessionsPerDomain = 16

// maxSamplersPerExporter bounds the sampler declarations one device holds for
// one protocol. A samplerId is a wire field and the scope is the device, so
// the table grows with what a sender announces rather than with its domains.
const maxSamplersPerExporter = 256

// templateField is one field specifier of a template. Enterprise is zero for
// an IANA information element and the enterprise number for a vendor one,
// which only IPFIX can express. An IPFIX variable-length field carries length
// 65535 and encodes each value's length in the record itself.
type templateField struct {
	fieldType  uint16
	length     uint16
	enterprise uint32
}

// template is one compiled template. Every field, refreshedAt included, is
// fixed before the store publishes it: a re-announcement swaps in a new
// template under the domain lock rather than restamping this one, which is
// what lets lookup hand its pointer out past the lock.
type template struct {
	fields []templateField
	// recordLen is the fixed record length the fields sum to. When
	// hasVariable is set it is the minimum length instead, counting one byte
	// per variable-length field.
	recordLen   int
	hasVariable bool
	// scopeCount is how many leading fields are scope fields; non-zero only
	// on an options template.
	scopeCount  int
	options     bool
	refreshedAt time.Time
}

// domainKey scopes templates as RFC 7011 requires: one exporter address and
// one Observation Domain ID together. Either alone lets two domains reusing
// one template ID corrupt each other's records.
//
// The protocol joins them because that pair is not enough here. Three
// decoders share this store, each numbering templates from 256 in a space of
// its own, and a v9 Source ID, an IPFIX Observation Domain ID and an sFlow
// sub-agent id are unrelated numbers that collide freely. A device exporting
// v9 and IPFIX at once sends both from one address, so without this a data
// set decodes against whichever protocol announced the id last -- silently,
// since the record walks to a length the fields agree on and reaches the
// aggregator as a measurement.
type domainKey struct {
	exporter netip.Addr
	odid     uint32
	proto    flow.Version
}

// samplerKey scopes a sampler table. An options record declaring Scope System
// describes the device, so a sampler announced in one domain measures records
// in every domain that device exports on the same protocol.
type samplerKey struct {
	exporter netip.Addr
	proto    flow.Version
}

// samplerEntry is one declaration and when it was last announced. A device
// re-sends its options on its own timer, so an entry it stops announcing is
// one whose sampler is gone: holding it would keep a device that renumbered
// its samplers reading as one declaring two rates.
type samplerEntry struct {
	rate     uint32
	lastSeen int64
}

// samplerRef names one declaration inside a device's table. Both identifiers
// are stored per domain, and how far a lookup reaches is the record's to
// decide: a samplerId announced under Cisco's Scope System describes the
// device, while IANA scopes a selectorId to the observation domain.
type samplerRef struct {
	odid uint32
	id   uint32
}

// samplerTable holds one device's sampling declarations for one protocol.
// named is keyed by the samplerId (IE 48) or selectorId (IE 302) a data
// record names; plain holds the rate a domain declared without naming one,
// keyed by that domain.
type samplerTable struct {
	mu    sync.RWMutex
	named map[samplerRef]samplerEntry
	plain map[uint32]samplerEntry
	// inherited is the one rate every declaration on this device agrees on,
	// and zero where they carry more than one. A record whose own domain
	// declared nothing takes it rather than a rate the device never tied
	// to it.
	inherited atomic.Uint32
	// sampled marks a device known to sample, by a declaration or by a
	// record naming its sampler. It never clears, so an expiry that empties
	// the table still reads as sampling.
	sampled atomic.Bool
}

// declare records one announcement, reporting whether the table took it and
// whether it replaced a rate the same domain had declared for the same
// identifier. A refusal leaves the table as it stood: evicting an entry the
// records still name would correct them by another sampler's rate.
func (t *samplerTable) declare(odid, id uint32, named bool, rate uint32, at int64) (ok, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ref := samplerRef{odid: odid, id: id}
	previous, held := t.plain[odid]
	if named {
		previous, held = t.named[ref]
	}
	if !held && len(t.named)+len(t.plain) >= maxSamplersPerExporter {
		return false, false
	}

	entry := samplerEntry{rate: rate, lastSeen: at}
	if named {
		if t.named == nil {
			t.named = make(map[samplerRef]samplerEntry)
		}
		t.named[ref] = entry
	} else {
		if t.plain == nil {
			t.plain = make(map[uint32]samplerEntry)
		}
		t.plain[odid] = entry
	}

	t.inherited.Store(t.soleRateLocked())
	t.sampled.Store(true)
	return true, held && previous.rate != rate
}

// expire drops every declaration the device stopped announcing before cutoff.
func (t *samplerTable) expire(cutoff int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for ref, entry := range t.named {
		if entry.lastSeen < cutoff {
			delete(t.named, ref)
		}
	}
	for odid, entry := range t.plain {
		if entry.lastSeen < cutoff {
			delete(t.plain, odid)
		}
	}
	t.inherited.Store(t.soleRateLocked())
}

// declaredRate resolves what a record naming one identifier takes, reporting
// whether the table settled the question at all.
//
// The record's own domain answers first. A samplerId then reaches across the
// device's domains and stops undecided where those disagree, correcting by
// one of several being a wrong reading rather than a missing one. A
// selectorId does not reach: IANA numbers it within the domain, so the same
// value elsewhere is a different selector.
func (t *samplerTable) declaredRate(odid, id uint32, deviceWide bool) (rate uint32, decided bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if entry, held := t.named[samplerRef{odid: odid, id: id}]; held {
		return entry.rate, true
	}
	if !deviceWide {
		return 0, false
	}

	var sole uint32
	for ref, entry := range t.named {
		if ref.id != id {
			continue
		}
		if sole != 0 && entry.rate != sole {
			return 0, true
		}
		sole = entry.rate
	}
	return sole, sole != 0
}

// plainRate returns what one domain declared without naming a sampler.
func (t *samplerTable) plainRate(odid uint32) uint32 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.plain[odid].rate
}

// markSampled records that the device samples on evidence other than a
// declaration, which is all NetFlow v5 can give: it names a sampler per
// record and declares no rate anywhere.
func (t *samplerTable) markSampled() {
	if !t.sampled.Load() {
		t.sampled.Store(true)
	}
}

// soleRateLocked returns the one rate every declaration agrees on, and zero
// where they carry none or more than one. Zero is never stored, so it doubles
// as the absent value. The table lock is held by the caller.
func (t *samplerTable) soleRateLocked() uint32 {
	var sole uint32
	for _, entry := range t.named {
		if sole != 0 && entry.rate != sole {
			return 0
		}
		sole = entry.rate
	}
	for _, entry := range t.plain {
		if sole != 0 && entry.rate != sole {
			return 0
		}
		sole = entry.rate
	}
	return sole
}

// domainState carries one observation domain's templates and the counters
// that are naturally per-domain rather than per-exporter.
type domainState struct {
	mu        sync.RWMutex
	templates map[uint16]*template

	// odid is the observation domain this state was opened for, held so the
	// record path reaches it without the store's key.
	odid uint32

	// lastSeen is when a datagram last named this domain, which the idle
	// sweep reads to free the exporter's budget again.
	lastSeen atomic.Int64

	// sessions holds one sequence position per transport session, keyed by
	// the source port that identifies it. They move under mu, which is not
	// the lock the sampler run below is held by.
	sessions map[uint16]*session
	// sequenceMissed counts the export packets the sequence numbers say were
	// lost, summed across those sessions so the published label set stays the
	// domain's. Reordering and device restarts reset a position instead.
	sequenceMissed atomic.Uint64

	// samplingRate is the packet sampling rate the domain's options declared
	// without naming a sampler, zero until one arrives.
	samplingRate atomic.Uint32
	// declared is the device's sampler table for this protocol, shared with
	// its other domains. Held here so the record path reaches it without a
	// store lock.
	declared *samplerTable

	// samplersMu guards samplers alone, so a datagram's sample loop never
	// waits on the lock a scrape reads the templates through.
	samplersMu sync.Mutex
	samplers   map[uint64]*samplerState
	// recent is the sampler the last sample named. A datagram carries one
	// sampler's samples together, so the next one usually names it again.
	recentID  uint64
	recentOne *samplerState
	// lateRun counts the samples read as late one after another. One agent
	// owns the domain, so its samplers restart together and share the count.
	lateRun int
	// samplersOldest lower-bounds the least lastSeen the map holds: a sampler
	// only moves its own forward and a new one is stamped now, so a sweep
	// before this ages out frees nothing.
	samplersOldest int64

	// samplingUnresolved counts the records that reached the end of the
	// correction precedence with nothing to apply.
	samplingUnresolved atomic.Uint64
	// samplerRateChanges counts the declarations that gave an identifier this
	// domain had already declared a different rate. Every record decoded
	// between the two was corrected by the rate then in force.
	samplerRateChanges atomic.Uint64

	// samplePool and samplesDropped accumulate the differences between one
	// sampler's readings. The agent restarts its own counters on its terms,
	// so what it reports is not what a Prometheus counter can carry.
	samplePool     atomic.Uint64
	samplesDropped atomic.Uint64
	// poolMeasured and dropsMeasured record that a difference was taken, which
	// a zero total cannot. The two guards are independent, so one reading may
	// be refused while the other is accumulated.
	poolMeasured  atomic.Bool
	dropsMeasured atomic.Bool

	// clockInversions counts the records whose flow ended before it began,
	// both instants withheld. clocksAnchored records that a pair was anchored
	// at all, which a zero count cannot: a template carrying no flow clock
	// never reaches the guard.
	clockInversions atomic.Uint64
	clocksAnchored  atomic.Bool
}

// countClockPair records one anchored flow clock pair. The load keeps the
// steady state off the write path, every record after the first finding the
// flag already set. A nil domain is a device at its budget, which loses the
// accounting rather than the record.
func (d *domainState) countClockPair(inverted bool) {
	if d == nil {
		return
	}
	if !d.clocksAnchored.Load() {
		d.clocksAnchored.Store(true)
	}
	if inverted {
		d.clockInversions.Add(1)
	}
}

// correctionFor settles the rate that measured one record naming id, and
// reports whether a rate is still owed to it. NetFlow's samplerId is the
// device's and PSAMP's selectorId the domain's, which isSampler separates.
//
// Cisco names an unsampled cache with samplerId 0 rather than leaving the
// element out, so a record naming an undeclared 0 is complete as it stands
// and inherits nothing. A device that does declare 0 is taken at its word,
// neither RFC 5477 nor IANA reserving the value.
func (d *domainState) correctionFor(id uint32, isSampler bool) (rate uint32, owed bool) {
	if rate, decided := d.declared.declaredRate(d.odid, id, isSampler); decided {
		return rate, rate == 0
	}
	if isSampler && id == unsampledSamplerID {
		return 0, false
	}
	return d.inheritedCorrection()
}

// inheritedCorrection is what a record naming no sampler takes: the domain's
// own declaration, then the one rate the whole device agrees on.
func (d *domainState) inheritedCorrection() (rate uint32, owed bool) {
	rate = d.rateInForce()
	return rate, rate == 0
}

// rateInForce is the rate in force for the domain itself.
func (d *domainState) rateInForce() uint32 {
	if rate := d.samplingRate.Load(); rate != 0 {
		return rate
	}
	return d.declared.inherited.Load()
}

// session is one transport session's position in a domain's sequence. RFC
// 7011 section 2 identifies a UDP session by its addresses and ports, and the
// sequence is numbered within one, so two export processes sharing an
// Observation Domain number independently and a shared position would read
// every alternation between them as loss.
type session struct {
	lastSeq uint32
	// lastSeen is when a datagram last arrived on this port, which the sweep
	// measures against the template TTL. Without it a device that renumbers
	// its source port on restart would spend a slot per restart and, past the
	// bound, leave its own sequence untracked for the life of the process --
	// silently, because a datagram on an untracked port still refreshes the
	// domain and keeps it from aging out.
	lastSeen int64
	// engine is the switching engine the position belongs to. A v5 or v8
	// device numbers a sequence per engine inside one session, and the odid a
	// domain is keyed by does not carry which one, so a change rebases.
	engine uint16
	// lateRun counts the messages read as late one after another.
	lateRun int
	init    bool
}

// sessionLocked returns one session's position, opening it on first use. A
// domain at its bound keeps the sessions it has rather than replacing them:
// an established position is worth more than the one a spoofed port would
// open, and the idle ones leave on the sweep. The domain lock is held by the
// caller.
func (d *domainState) sessionLocked(port uint16, at int64) *session {
	if s, ok := d.sessions[port]; ok {
		s.lastSeen = at
		return s
	}
	if len(d.sessions) >= maxSessionsPerDomain {
		return nil
	}

	if d.sessions == nil {
		d.sessions = make(map[uint16]*session, 1)
	}
	s := &session{lastSeen: at}
	d.sessions[port] = s
	return s
}

// pruneIdleSessionsLocked drops the sessions no datagram has arrived on since
// the cutoff, returning their slots. The domain lock is held by the caller.
func (d *domainState) pruneIdleSessionsLocked(cutoff int64) {
	for port, s := range d.sessions {
		if s.lastSeen < cutoff {
			delete(d.sessions, port)
		}
	}
}

// samplerState is one sampler's last reading, which the next one is measured
// from.
type samplerState struct {
	seq      uint32
	rate     uint32
	pool     uint32
	drops    uint32
	lastSeen int64
}

// templateStore indexes the per-domain state. Domains appear on first use,
// are bounded per exporter, and are swept once idle, so their count follows
// the fleet rather than the traffic.
type templateStore struct {
	mu      sync.RWMutex
	domains map[domainKey]*domainState
	// samplerTables holds each device's sampler declarations per protocol,
	// which outlive the domain whose options record announced them.
	samplerTables map[samplerKey]*samplerTable
	// perExporter counts each device's live domains against its budget.
	perExporter map[netip.Addr]int

	// domainsRefused counts the datagrams the budget turned away, one per
	// datagram naming a domain past it, so the loss is visible rather than
	// silent.
	domainsRefused atomic.Uint64

	// samplersRefused counts the flow samples turned away at a domain's
	// sampler budget. The sample still decodes; only its counters are lost.
	samplersRefused atomic.Uint64

	// declarationsRefused counts the sampling declarations turned away at a
	// device's table budget. Records naming a refused sampler fall back to
	// the device's own rate rather than being corrected by another's.
	declarationsRefused atomic.Uint64

	maxFields int
	ttl       time.Duration
	now       func() time.Time
}

// newTemplateStore creates a store enforcing the configured limits.
func newTemplateStore(cfg config.Parser) *templateStore {
	return &templateStore{
		domains:       make(map[domainKey]*domainState),
		samplerTables: make(map[samplerKey]*samplerTable),
		perExporter:   make(map[netip.Addr]int),
		maxFields:     cfg.MaxFieldsPerTemplate,
		ttl:           cfg.TemplateTTL,
		now:           time.Now,
	}
}

// domain returns one observation domain's state, creating it on first use and
// stamping it as seen. It returns nil once the exporter is at its domain
// budget, or once the fleet is: the identifier and the source address are both
// wire fields, so either map is unbounded from the wire without a budget. A
// device already holding domains keeps its own.
func (s *templateStore) domain(key domainKey) *domainState {
	now := s.now().UnixNano()

	s.mu.RLock()
	d, ok := s.domains[key]
	s.mu.RUnlock()
	if ok {
		d.lastSeen.Store(now)
		return d
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.domains[key]; ok {
		d.lastSeen.Store(now)
		return d
	}
	owned := s.perExporter[key.exporter]
	if owned >= maxDomainsPerExporter {
		s.domainsRefused.Add(1)
		return nil
	}
	if owned == 0 && len(s.perExporter) >= maxExporters {
		s.domainsRefused.Add(1)
		return nil
	}

	tk := samplerKey{exporter: key.exporter, proto: key.proto}
	table, held := s.samplerTables[tk]
	if !held {
		table = &samplerTable{}
		s.samplerTables[tk] = table
	}

	d = &domainState{templates: make(map[uint16]*template), odid: key.odid, declared: table}
	d.lastSeen.Store(now)
	s.domains[key] = d
	s.perExporter[key.exporter]++
	return d
}

// sweepDomains drops every domain idle since before cutoff, returning its slot
// to the exporter's budget, and reports how many went.
func (s *templateStore) sweepDomains(cutoff int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	evicted := 0
	for key, d := range s.domains {
		if d.lastSeen.Load() >= cutoff {
			continue
		}

		delete(s.domains, key)
		s.perExporter[key.exporter]--
		if s.perExporter[key.exporter] <= 0 {
			delete(s.perExporter, key.exporter)
		}
		evicted++
	}

	// A domain a device still speaks to survives the sweep whole, so its own
	// idle state is freed here rather than with it.
	for _, d := range s.domains {
		d.mu.Lock()
		d.pruneIdleSessionsLocked(cutoff)
		d.mu.Unlock()
	}
	s.sweepSamplerTablesLocked(cutoff)
	return evicted
}

// sweepSamplerTablesLocked drops every declaration the device stopped
// announcing, then restates what each surviving domain declared for itself.
// A table is freed only once no domain holds it: the domains share the
// pointer, so freeing one still referenced would take later declarations
// somewhere no scrape reads. The store lock is held by the caller.
func (s *templateStore) sweepSamplerTablesLocked(cutoff int64) {
	for _, table := range s.samplerTables {
		table.expire(cutoff)
	}

	live := make(map[samplerKey]struct{}, len(s.domains))
	for key, d := range s.domains {
		live[samplerKey{exporter: key.exporter, proto: key.proto}] = struct{}{}
		d.samplingRate.Store(d.declared.plainRate(key.odid))
	}
	for key := range s.samplerTables {
		if _, held := live[key]; !held {
			delete(s.samplerTables, key)
		}
	}
}

// declareSampler records one options announcement onto the device's table,
// counting a refusal where the table is at its budget.
func (s *templateStore) declareSampler(d *domainState, odid, id uint32, named bool, rate uint32) {
	ok, changed := d.declared.declare(odid, id, named, rate, d.lastSeen.Load())
	if !ok {
		s.declarationsRefused.Add(1)
	}
	if changed {
		d.samplerRateChanges.Add(1)
	}
}

// cutoff is the instant before which state counts as idle: one template TTL
// back from the clock that stamps every announcement.
func (s *templateStore) cutoff() int64 {
	return s.now().Add(-s.ttl).UnixNano()
}

// refused reports how many datagrams the budget turned away.
func (s *templateStore) refused() uint64 {
	return s.domainsRefused.Load()
}

// refusedDeclarations reports how many sampling declarations a device's table
// budget turned away.
func (s *templateStore) refusedDeclarations() uint64 {
	return s.declarationsRefused.Load()
}

// refusedSamplers reports how many flow samples the sampler budget turned away.
func (s *templateStore) refusedSamplers() uint64 {
	return s.samplersRefused.Load()
}

// add registers or refreshes one template. A full domain drops expired
// templates first and rejects the addition when nothing expired.
func (s *templateStore) add(key domainKey, id uint16, t *template) bool {
	d := s.domain(key)
	if d == nil {
		return false
	}
	now := s.now()
	t.refreshedAt = now

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.templates[id]; !exists && len(d.templates) >= maxTemplatesPerDomain {
		d.pruneExpiredLocked(now, s.ttl)
		if len(d.templates) >= maxTemplatesPerDomain {
			return false
		}
	}

	d.templates[id] = t
	return true
}

// pruneExpiredLocked drops every template past the TTL. The domain lock is
// held by the caller.
func (d *domainState) pruneExpiredLocked(now time.Time, ttl time.Duration) {
	for id, t := range d.templates {
		if now.Sub(t.refreshedAt) > ttl {
			delete(d.templates, id)
		}
	}
}

// lookup returns one template, treating a template past the TTL as absent:
// an orphaned template decoding new records would trust a schema the device
// may have replaced.
func (s *templateStore) lookup(key domainKey, id uint16) (*template, bool) {
	d := s.domain(key)
	if d == nil {
		return nil, false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	t, ok := d.templates[id]
	if !ok || s.now().Sub(t.refreshedAt) > s.ttl {
		return nil, false
	}
	return t, true
}

// trackSequence advances one domain's export sequence and counts the packets
// the numbers say were skipped. A small step backwards is network reordering
// and is ignored so the packet it overtook is not counted missing twice; any
// larger jump in either direction reads as a device restart and resets the
// base without counting.
func (d *domainState) trackSequence(port uint16, seq uint32) {
	const (
		forwardWindow = 1 << 30
		reorderWindow = 1024
	)

	d.mu.Lock()
	defer d.mu.Unlock()

	s := d.sessionLocked(port, d.lastSeen.Load())
	if s == nil {
		return
	}
	if !s.init {
		s.init = true
		s.lastSeq = seq
		return
	}

	switch diff := seq - s.lastSeq; {
	case diff == 0:
		// A duplicate; nothing moved.
	case diff < forwardWindow:
		if diff > 1 {
			d.sequenceMissed.Add(uint64(diff - 1))
		}
		s.lastSeq = seq
	case diff > ^uint32(0)-reorderWindow:
		// A late packet from before the current position.
	default:
		s.lastSeq = seq
	}
}

// trackSamplerLocked folds one flow sample's counters into the domain's
// totals. The sample sequence says whether two readings are consecutive: a
// step the agent did not take, or a rate it did not hold before, rebases the
// sampler rather than accumulating a difference neither reading covers.
// The sampler lock is held across the datagram by the caller, which is where
// the samples of one domain arrive in wire order.
func (s *templateStore) trackSamplerLocked(d *domainState, id uint64, seq, rate, pool, drops uint32) {
	const (
		forwardWindow = 1 << 30
		reorderWindow = 1024
	)

	at := d.lastSeen.Load()

	last := d.recentOne
	if last == nil || d.recentID != id {
		var ok bool
		if last, ok = d.samplers[id]; !ok {
			if len(d.samplers) >= maxSamplersPerDomain {
				if at-d.samplersOldest <= int64(s.ttl) {
					s.samplersRefused.Add(1)
					return
				}
				d.pruneIdleSamplersLocked(at, s.ttl)
				if len(d.samplers) >= maxSamplersPerDomain {
					s.samplersRefused.Add(1)
					return
				}
			}
			if d.samplers == nil {
				d.samplers = make(map[uint64]*samplerState)
			}
			last = &samplerState{seq: seq, rate: rate, pool: pool, drops: drops, lastSeen: at}
			d.samplers[id] = last
			d.recentID, d.recentOne = id, last
			return
		}
		d.recentID, d.recentOne = id, last
	}

	switch step := seq - last.seq; {
	case step > ^uint32(0)-reorderWindow && pool <= last.pool && d.lateRun < maxLateRun:
		// A late sample from before the current position.
		d.lateRun++
		return
	case step >= forwardWindow || rate != last.rate:
		// A restart or a reconfiguration, which the counters do not span.
	default:
		// The counters are uint32 on the wire and are held at that width, so
		// a wrap of their own reads as the step the agent took.
		if delta := pool - last.pool; delta < forwardWindow {
			d.samplePool.Add(uint64(delta))
			d.poolMeasured.Store(true)
		}
		if delta := drops - last.drops; delta < forwardWindow {
			d.samplesDropped.Add(uint64(delta))
			d.dropsMeasured.Store(true)
		}
	}

	d.lateRun = 0
	last.seq, last.rate, last.pool, last.drops, last.lastSeen = seq, rate, pool, drops, at
}

// pruneIdleSamplersLocked drops every sampler silent for longer than the TTL.
// The sampler lock is held by the caller.
func (d *domainState) pruneIdleSamplersLocked(now int64, ttl time.Duration) {
	cutoff := now - int64(ttl)
	oldest := now
	for id, last := range d.samplers {
		if last.lastSeen < cutoff {
			delete(d.samplers, id)
			continue
		}
		if last.lastSeen < oldest {
			oldest = last.lastSeen
		}
	}
	d.samplersOldest = oldest
	// The cache may name one that went; the map is what holds a sampler.
	d.recentOne = nil
}

// trackRecordSequence advances a sequence that counts records rather than
// packets, which v5, v8 and IPFIX all number that way. When a message's own
// record count is unknown the tracking resets instead of guessing, and a
// message from another engine rebases because its sequence is its own.
//
// A message overtaken in flight is held rather than rewinding the base: the
// records it carries were counted missing when it was skipped, and rewinding
// counts them a second time on the next one to arrive. A run longer than
// reordering reaches is a restart, which rebases without counting.
func (d *domainState) trackRecordSequence(port uint16, seq, records uint32, engine uint16, complete bool) {
	const (
		forwardWindow = 1 << 30
		reorderWindow = 1024
	)

	d.mu.Lock()
	defer d.mu.Unlock()

	s := d.sessionLocked(port, d.lastSeen.Load())
	if s == nil {
		return
	}
	if !s.init || engine != s.engine {
		s.init = complete
		s.engine = engine
		s.lastSeq = seq + records
		s.lateRun = 0
		return
	}

	// lastSeq holds the sequence expected on the next message.
	switch diff := seq - s.lastSeq; {
	case diff == 0:
		// In order; only the base advances.
	case diff > ^uint32(0)-reorderWindow && s.lateRun < maxLateRun:
		s.lateRun++
		return
	case diff < forwardWindow:
		d.sequenceMissed.Add(uint64(diff))
	default:
		// A restart, which the counter does not span.
	}

	s.lateRun = 0
	s.init = complete
	s.lastSeq = seq + records
}

// counts reports how many data and options templates the domain holds now.
func (d *domainState) counts(now time.Time, ttl time.Duration) (data, options int) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, t := range d.templates {
		if now.Sub(t.refreshedAt) > ttl {
			continue
		}
		if t.options {
			options++
		} else {
			data++
		}
	}
	return data, options
}

// DomainSnapshot is one observation domain's state at one instant. Version
// travels with the pair because three decoders number their domains
// independently, so an exporter and an Observation Domain ID do not name one.
type DomainSnapshot struct {
	Exporter         netip.Addr
	ODID             uint32
	Version          flow.Version
	Templates        int
	OptionsTemplates int
	SequenceMissed   uint64
	// SamplingUnresolved counts the records taken uncorrected, and Sampled
	// carries whether the device ever declared, which a zero cannot.
	SamplingUnresolved uint64
	Sampled            bool
	// SamplerRateChanges counts the declarations that replaced a rate this
	// domain had already declared for the same identifier.
	SamplerRateChanges uint64
	// SamplingRate is the rate in force for the domain, declared by its own
	// options or inherited from the device's single declaration. It is zero
	// where neither settles on one.
	SamplingRate uint32
	// SamplePool and SamplesDropped are the sFlow samplers' own counters,
	// summed across the domain. The Measured flags carry whether a difference
	// was taken at all, which a total of zero cannot.
	SamplePool     uint64
	SamplesDropped uint64
	PoolMeasured   bool
	DropsMeasured  bool
	// ClockInversions counts the records whose two instants were withheld for
	// ending before they began, and ClocksAnchored carries whether a pair was
	// anchored at all, which a zero cannot.
	ClockInversions uint64
	ClocksAnchored  bool
}

// SamplerSnapshot is one rate a device declared for one named sampler.
type SamplerSnapshot struct {
	Exporter netip.Addr
	Version  flow.Version
	ODID     uint32
	Sampler  uint32
	Rate     uint32
}

// samplerSnapshot reads every named declaration. A rate declared without a
// samplerId is the domain's own and reaches the metrics through DomainSnapshot.
func (s *templateStore) samplerSnapshot() []SamplerSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshots := make([]SamplerSnapshot, 0, len(s.samplerTables))
	for key, table := range s.samplerTables {
		table.mu.RLock()
		for ref, entry := range table.named {
			snapshots = append(snapshots, SamplerSnapshot{
				Exporter: key.exporter,
				Version:  key.proto,
				ODID:     ref.odid,
				Sampler:  ref.id,
				Rate:     entry.rate,
			})
		}
		table.mu.RUnlock()
	}
	return snapshots
}

// snapshot reads every domain's state.
func (s *templateStore) snapshot() []DomainSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()
	snapshots := make([]DomainSnapshot, 0, len(s.domains))
	for key, d := range s.domains {
		data, options := d.counts(now, s.ttl)
		snapshots = append(snapshots, DomainSnapshot{
			Exporter:           key.exporter,
			ODID:               key.odid,
			Version:            key.proto,
			Templates:          data,
			OptionsTemplates:   options,
			SequenceMissed:     d.sequenceMissed.Load(),
			SamplingUnresolved: d.samplingUnresolved.Load(),
			Sampled:            d.declared.sampled.Load(),
			SamplerRateChanges: d.samplerRateChanges.Load(),
			SamplingRate:       d.rateInForce(),
			SamplePool:         d.samplePool.Load(),
			SamplesDropped:     d.samplesDropped.Load(),
			PoolMeasured:       d.poolMeasured.Load(),
			DropsMeasured:      d.dropsMeasured.Load(),
			ClockInversions:    d.clockInversions.Load(),
			ClocksAnchored:     d.clocksAnchored.Load(),
		})
	}
	return snapshots
}
