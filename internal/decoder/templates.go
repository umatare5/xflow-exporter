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

// maxTemplateFieldsPerExporter bounds the field specifiers one device's
// templates hold across its domains and sessions. The domain and template
// bounds alone multiply to millions per source address, which a forged one
// can fill; a device carries a few hundred.
const maxTemplateFieldsPerExporter = 65536

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

// domainKey scopes templates to one exporter address and one Observation
// Domain ID together, since either alone lets two domains reusing one
// template ID corrupt each other's records. templateRef narrows them to one
// transport session inside the domain.
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

// templateRef names one template inside a domain. RFC 7011 section 3.4.1 makes
// a Template ID unique only within the transport session that announced it,
// and a Cisco router exporting its traditional cache beside a Flexible NetFlow
// monitor numbers the two independently under one Source ID. Keyed by the ID
// alone, each announcement swapped in the other's layout and the data decoded
// against it. The source port names the session, the address being the
// domain's.
type templateRef struct {
	port uint16
	id   uint16
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

// scopedRef names a declaration an options record tied to less than the
// device: one template of one transport session, the records arriving on one
// interface, or a whole domain named by its identifier. A template ID means
// something only inside its session (RFC 7011 section 3.4.1), so port joins it.
type scopedRef struct {
	kind  scopeKind
	odid  uint32
	port  uint16
	value uint32
}

// scopeKind is what a scoped declaration's value identifies.
type scopeKind uint8

const (
	scopeTemplate scopeKind = iota + 1
	scopeInterface
	scopeDomain
)

// samplerTable holds one device's sampling declarations for one protocol.
// named is keyed by the samplerId (IE 48) or selectorId (IE 302) a data
// record names; plain holds the rate a domain declared without naming one,
// keyed by that domain.
type samplerTable struct {
	mu    sync.RWMutex
	named map[samplerRef]samplerEntry
	plain map[uint32]samplerEntry
	// scoped holds the rates tied to what a scopedRef names. None of them is
	// lent to a record it does not name, so none feeds inherited either.
	scoped map[scopedRef]samplerEntry
	// hasScoped lets a record skip the table lock on a device that scopes
	// nothing, which is every device before its first scoped declaration.
	hasScoped atomic.Bool
	// inherited is the one rate every declaration on this device agrees on,
	// and zero where they carry more than one. A domain no declaration names,
	// its own or another's scoped to it, takes it rather than a rate the
	// device never tied to it.
	inherited atomic.Uint32
	// sampled marks a device known to sample, by a declaration or by a
	// record naming its selection process. It never clears, so an expiry
	// that empties the table still reads as sampling.
	sampled atomic.Bool
	// declaredZero marks a device that declared a rate for samplerId 0,
	// which takes the identifier out of Cisco's unsampled-cache convention
	// for good. It never clears either: a declaration the device stops
	// announcing leaves its records owed a rate rather than complete.
	declaredZero atomic.Bool
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
	if !held && t.sizeLocked() >= maxSamplersPerExporter {
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
	if named && id == unsampledSamplerID {
		t.declaredZero.Store(true)
	}
	return true, held && previous.rate != rate
}

// declareScoped records one scoped announcement, reporting as declare does.
func (t *samplerTable) declareScoped(ref scopedRef, rate uint32, at int64) (ok, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	previous, held := t.scoped[ref]
	if !held && t.sizeLocked() >= maxSamplersPerExporter {
		return false, false
	}
	if t.scoped == nil {
		t.scoped = make(map[scopedRef]samplerEntry)
	}
	t.scoped[ref] = samplerEntry{rate: rate, lastSeen: at}
	t.hasScoped.Store(true)
	t.sampled.Store(true)
	return true, held && previous.rate != rate
}

// scopedRate returns the rate declared for exactly what ref names.
func (t *samplerTable) scopedRate(ref scopedRef) (uint32, bool) {
	if !t.hasScoped.Load() {
		return 0, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, held := t.scoped[ref]
	return entry.rate, held
}

// sizeLocked is how many declarations the budget counts. The table lock is
// held by the caller.
func (t *samplerTable) sizeLocked() int {
	return len(t.named) + len(t.plain) + len(t.scoped)
}

// expire drops every declaration the device stopped announcing before cutoff.
func (t *samplerTable) expire(cutoff int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for ref, entry := range t.scoped {
		if entry.lastSeen < cutoff {
			delete(t.scoped, ref)
		}
	}
	t.hasScoped.Store(len(t.scoped) > 0)

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
// declaration: a record naming a sampler or a selector. NetFlow v5 has
// nothing else to give, declaring no rate anywhere, and a v9 or IPFIX device
// reads as sampling before its first announcement arrives.
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
	templates map[templateRef]*template
	// fields is the field specifiers templates hold, charged to the device's
	// budget as well so evicting the domain returns them in one step.
	fields int
	budget *exporterBudget

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

	// aggregateZeroFlows counts the records this domain routed as an
	// aggregate on a declared flow count of zero, which leaves them in the
	// exporters table alone. aggregatesReported records that a count was
	// declared at all, which a zero cannot.
	aggregateZeroFlows atomic.Uint64
	aggregatesReported atomic.Bool
}

// countAggregate records one record carrying a declared flow count. A nil
// domain is a device at its budget, which loses the accounting rather than
// the record.
func (d *domainState) countAggregate(empty bool) {
	if d == nil {
		return
	}
	if !d.aggregatesReported.Load() {
		d.aggregatesReported.Store(true)
	}
	if empty {
		d.aggregateZeroFlows.Add(1)
	}
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
// Cisco names an unsampled cache with samplerId 0 where its record collects
// or matches the sampler, so a record naming an undeclared 0 is complete as
// it stands and inherits nothing. A device that does declare 0 is taken at
// its word, neither RFC 5477 nor IANA reserving the value, and an expiry then
// owes those records a rate rather than handing them one the device never
// tied to that cache.
//
// Naming any other identifier is the device saying it samples, which every
// protocol states the same way while only v9 and IPFIX can also declare it.
func (d *domainState) correctionFor(id uint32, isSampler bool) (rate uint32, owed bool) {
	unsampled := isSampler && id == unsampledSamplerID
	if !unsampled {
		d.declared.markSampled()
	}

	if rate, decided := d.declared.declaredRate(d.odid, id, isSampler); decided {
		return rate, rate == 0
	}
	if unsampled {
		return 0, d.declared.declaredZero.Load()
	}
	return d.inheritedCorrection()
}

// scopedCorrection is what a declaration scoped below the domain settles for
// a record naming no sampler: its own template's rate, then the rate of the
// interface it arrived on. An ifIndex of zero names no interface (RFC 2863).
func (d *domainState) scopedCorrection(tpl templateRef, inputIf uint32) (rate uint32, held bool) {
	ref := scopedRef{kind: scopeTemplate, odid: d.odid, port: tpl.port, value: uint32(tpl.id)}
	if rate, held := d.declared.scopedRate(ref); held {
		return rate, true
	}
	if inputIf == 0 {
		return 0, false
	}
	return d.declared.scopedRate(scopedRef{kind: scopeInterface, odid: d.odid, value: inputIf})
}

// inheritedCorrection is what a record the precedence has not settled takes:
// the rate in force for its domain.
func (d *domainState) inheritedCorrection() (rate uint32, owed bool) {
	rate = d.rateInForce()
	return rate, rate == 0
}

// rateInForce is the rate in force for the domain itself: its own
// declaration, then one another domain's options scoped to it, then the rate
// the device agrees on.
func (d *domainState) rateInForce() uint32 {
	if rate := d.samplingRate.Load(); rate != 0 {
		return rate
	}
	if rate, held := d.declared.scopedRate(scopedRef{kind: scopeDomain, value: d.odid}); held {
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

// exporterBudget is one device's share of the store's bounds. Its domains
// share the pointer, so a template is charged against it under the domain
// lock alone.
type exporterBudget struct {
	// domains counts the device's live domains; the store lock guards it.
	domains int
	fields  atomic.Int64
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
	// perExporter holds each device's budget while it has a live domain.
	perExporter map[netip.Addr]*exporterBudget

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
		perExporter:   make(map[netip.Addr]*exporterBudget),
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
	budget := s.perExporter[key.exporter]
	if budget != nil && budget.domains >= maxDomainsPerExporter {
		s.domainsRefused.Add(1)
		return nil
	}
	if budget == nil && len(s.perExporter) >= maxExporters {
		s.domainsRefused.Add(1)
		return nil
	}

	tk := samplerKey{exporter: key.exporter, proto: key.proto}
	table, held := s.samplerTables[tk]
	if !held {
		table = &samplerTable{}
		s.samplerTables[tk] = table
	}

	if budget == nil {
		budget = &exporterBudget{}
		s.perExporter[key.exporter] = budget
	}
	budget.domains++

	d = &domainState{
		templates: make(map[templateRef]*template),
		budget:    budget,
		odid:      key.odid,
		declared:  table,
	}
	d.lastSeen.Store(now)
	s.domains[key] = d
	return d
}

// sweepDomains drops every domain idle since before cutoff, returning its slot
// to the exporter's budget, and reports how many went.
func (s *templateStore) sweepDomains(cutoff int64) int {
	evicted, live := s.evictIdleDomains(cutoff)

	// A domain a device still speaks to survives the sweep whole, so its own
	// idle state is freed here rather than with it. Each is walked under its
	// own lock alone: the store lock held across every template would stall
	// every device's decode for the walk.
	now := s.now()
	for _, d := range live {
		d.mu.Lock()
		d.pruneIdleSessionsLocked(cutoff)
		d.pruneExpiredLocked(now, s.ttl)
		d.mu.Unlock()
	}
	return evicted
}

// evictIdleDomains drops every domain idle since before cutoff and the
// declarations its device stopped announcing, and returns the domains left.
func (s *templateStore) evictIdleDomains(cutoff int64) (evicted int, live []*domainState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, d := range s.domains {
		if d.lastSeen.Load() >= cutoff {
			continue
		}

		delete(s.domains, key)
		d.mu.Lock()
		d.budget.fields.Add(-int64(d.fields))
		d.mu.Unlock()
		d.budget.domains--
		if d.budget.domains <= 0 {
			delete(s.perExporter, key.exporter)
		}
		evicted++
	}
	s.sweepSamplerTablesLocked(cutoff)

	live = make([]*domainState, 0, len(s.domains))
	for _, d := range s.domains {
		live = append(live, d)
	}
	return evicted, live
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

// declareScoped records one scoped announcement onto the device's table,
// counting as declareSampler does.
func (s *templateStore) declareScoped(d *domainState, ref scopedRef, rate uint32) {
	ok, changed := d.declared.declareScoped(ref, rate, d.lastSeen.Load())
	if !ok {
		s.declarationsRefused.Add(1)
	}
	if changed {
		d.samplerRateChanges.Add(1)
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

// add registers or refreshes one template. A domain or device at its bound
// drops the domain's expired templates first and rejects the addition when
// that frees too little. A rejected redefinition still withdraws the layout
// its ID held: RFC 3954 section 9 and RFC 7011 section 8.4 replace it with
// the one announced, so the device's data no longer fits it.
func (s *templateStore) add(key domainKey, port, id uint16, t *template) bool {
	d := s.domain(key)
	if d == nil {
		return false
	}
	now := s.now()
	t.refreshedAt = now
	ref := templateRef{port: port, id: id}

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.fitsLocked(ref, t) {
		d.pruneExpiredLocked(now, s.ttl)
		if !d.fitsLocked(ref, t) {
			d.dropLocked(ref)
			return false
		}
	}

	d.chargeLocked(len(t.fields) - d.heldFieldsLocked(ref))
	d.templates[ref] = t
	return true
}

// fitsLocked reports whether the domain and its device can hold t under ref,
// a refresh counting only the fields it adds. The domain lock is held by the
// caller.
func (d *domainState) fitsLocked(ref templateRef, t *template) bool {
	if _, exists := d.templates[ref]; !exists && len(d.templates) >= maxTemplatesPerDomain {
		return false
	}
	grow := len(t.fields) - d.heldFieldsLocked(ref)
	return d.budget.fields.Load()+int64(grow) <= maxTemplateFieldsPerExporter
}

// heldFieldsLocked reports the fields the template under ref holds, zero when
// there is none. The domain lock is held by the caller.
func (d *domainState) heldFieldsLocked(ref templateRef) int {
	if t, ok := d.templates[ref]; ok {
		return len(t.fields)
	}
	return 0
}

// chargeLocked moves the domain's and its device's field counts together.
// The domain lock is held by the caller.
func (d *domainState) chargeLocked(fields int) {
	d.fields += fields
	d.budget.fields.Add(int64(fields))
}

// pruneExpiredLocked drops every template past the TTL. The domain lock is
// held by the caller.
func (d *domainState) pruneExpiredLocked(now time.Time, ttl time.Duration) {
	for ref, t := range d.templates {
		if now.Sub(t.refreshedAt) > ttl {
			d.dropLocked(ref)
		}
	}
}

// dropLocked removes the template under ref, if one is held, and returns its
// fields to the budget. The domain lock is held by the caller.
func (d *domainState) dropLocked(ref templateRef) {
	if t, ok := d.templates[ref]; ok {
		d.chargeLocked(-len(t.fields))
		delete(d.templates, ref)
	}
}

// lookup returns one template, treating a template past the TTL as absent:
// an orphaned template decoding new records would trust a schema the device
// may have replaced.
func (s *templateStore) lookup(key domainKey, port, id uint16) (*template, bool) {
	d := s.domain(key)
	if d == nil {
		return nil, false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	t, ok := d.templates[templateRef{port: port, id: id}]
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
	// carries whether the device is known to sample, which a zero cannot.
	SamplingUnresolved uint64
	Sampled            bool
	// SamplerRateChanges counts the declarations that replaced a rate this
	// domain had already declared for the same identifier.
	SamplerRateChanges uint64
	// SamplingRate is the rate in force for the domain: its own declaration,
	// one another domain's options scoped to it, or the device's single rate.
	// It is zero where none settles on one.
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
	// AggregateZeroFlows counts the records routed as an aggregate on a
	// declared flow count of zero, and AggregatesReported carries whether
	// one was declared at all.
	AggregateZeroFlows uint64
	AggregatesReported bool
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
			AggregateZeroFlows: d.aggregateZeroFlows.Load(),
			AggregatesReported: d.aggregatesReported.Load(),
		})
	}
	return snapshots
}
