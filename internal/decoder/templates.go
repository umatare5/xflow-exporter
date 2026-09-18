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

// samplerTable holds one device's sampling declarations for one protocol.
// rates is keyed by the samplerId (IE 48) a data record names; plain holds
// the rate a domain declared without naming one, keyed by that domain.
type samplerTable struct {
	mu    sync.RWMutex
	rates map[uint32]samplerEntry
	plain map[uint32]samplerEntry
	// inherited is the one rate every declaration on this device agrees on,
	// and zero where they carry more than one. A record whose own domain
	// declared nothing takes it rather than a rate the device never tied
	// to it.
	inherited atomic.Uint32
	// sampled marks a device that has declared at least once. It never
	// clears, so an expiry that empties the table still reads as sampling.
	sampled atomic.Bool
}

// declare records one announcement, reporting false where the device is at
// its budget. A refusal leaves the table as it stood: evicting an entry the
// records still name would correct them by another sampler's rate.
func (t *samplerTable) declare(odid, samplerID uint32, named bool, rate uint32, at int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	key, target := odid, &t.plain
	if named {
		key, target = samplerID, &t.rates
	}
	if _, held := (*target)[key]; !held {
		if len(t.rates)+len(t.plain) >= maxSamplersPerExporter {
			return false
		}
		if *target == nil {
			*target = make(map[uint32]samplerEntry)
		}
	}
	(*target)[key] = samplerEntry{rate: rate, lastSeen: at}
	t.inherited.Store(soleRate(t.rates, t.plain))
	t.sampled.Store(true)
	return true
}

// expire drops every declaration the device stopped announcing before cutoff.
func (t *samplerTable) expire(cutoff int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, set := range []map[uint32]samplerEntry{t.rates, t.plain} {
		for key, entry := range set {
			if entry.lastSeen < cutoff {
				delete(set, key)
			}
		}
	}
	t.inherited.Store(soleRate(t.rates, t.plain))
}

func (t *samplerTable) rateFor(samplerID uint32) (uint32, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.rates[samplerID]
	return entry.rate, ok
}

// plainRate returns what one domain declared without naming a sampler.
func (t *samplerTable) plainRate(odid uint32) uint32 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.plain[odid].rate
}

// soleRate returns the one rate every declaration agrees on, and zero where
// they carry none or more than one. Zero is never stored, so it doubles as
// the absent value.
func soleRate(sets ...map[uint32]samplerEntry) uint32 {
	var sole uint32
	for _, set := range sets {
		for _, entry := range set {
			if sole != 0 && entry.rate != sole {
				return 0
			}
			sole = entry.rate
		}
	}
	return sole
}

// domainState carries one observation domain's templates and the counters
// that are naturally per-domain rather than per-exporter.
type domainState struct {
	mu        sync.RWMutex
	templates map[uint16]*template

	// lastSeen is when a datagram last named this domain, which the idle
	// sweep reads to free the exporter's budget again.
	lastSeen atomic.Int64

	// sequence gap tracking. seqInit, lastSeq, seqEngine and seqLateRun move
	// under mu, which is not the lock the sampler run below is held by.
	seqInit bool
	lastSeq uint32
	// seqEngine is the switching engine the tracked position belongs to. A v5
	// or v8 device numbers a sequence per engine, and the odid a domain is
	// keyed by does not carry which one, so a change rebases.
	seqEngine uint16
	// seqLateRun counts the messages read as late one after another.
	seqLateRun int
	// SequenceMissed counts export packets the sequence numbers say were
	// lost. Reordering and device restarts reset the base instead.
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
}

// rateInForce is the rate a record carrying no samplerId takes: the domain's
// own declaration, then the one rate the whole device agrees on.
func (d *domainState) rateInForce() uint32 {
	if rate := d.samplingRate.Load(); rate != 0 {
		return rate
	}
	return d.declared.inherited.Load()
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
// budget: the identifier is a wire field, so an unbounded map here is
// reachable from one permitted source address.
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
	if s.perExporter[key.exporter] >= maxDomainsPerExporter {
		s.domainsRefused.Add(1)
		return nil
	}

	tk := samplerKey{exporter: key.exporter, proto: key.proto}
	table, held := s.samplerTables[tk]
	if !held {
		table = &samplerTable{}
		s.samplerTables[tk] = table
	}

	d = &domainState{templates: make(map[uint16]*template), declared: table}
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
func (s *templateStore) declareSampler(d *domainState, odid, samplerID uint32, named bool, rate uint32) {
	if !d.declared.declare(odid, samplerID, named, rate, d.lastSeen.Load()) {
		s.declarationsRefused.Add(1)
	}
}

// sweep drops the domains idle for longer than the template TTL. A domain
// nobody has named for that long carries only templates that have expired
// with it.
func (s *templateStore) sweep() int {
	return s.sweepDomains(s.now().Add(-s.ttl).UnixNano())
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

// remove withdraws one template.
func (s *templateStore) remove(key domainKey, id uint16) {
	d := s.domain(key)
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.templates, id)
}

// removeAll withdraws every template of one kind in the domain.
func (s *templateStore) removeAll(key domainKey, options bool) {
	d := s.domain(key)
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, t := range d.templates {
		if t.options == options {
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
func (d *domainState) trackSequence(seq uint32) {
	const (
		forwardWindow = 1 << 30
		reorderWindow = 1024
	)

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.seqInit {
		d.seqInit = true
		d.lastSeq = seq
		return
	}

	switch diff := seq - d.lastSeq; {
	case diff == 0:
		// A duplicate; nothing moved.
	case diff < forwardWindow:
		if diff > 1 {
			d.sequenceMissed.Add(uint64(diff - 1))
		}
		d.lastSeq = seq
	case diff > ^uint32(0)-reorderWindow:
		// A late packet from before the current position.
	default:
		d.lastSeq = seq
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
func (d *domainState) trackRecordSequence(seq, records uint32, engine uint16, complete bool) {
	const (
		forwardWindow = 1 << 30
		reorderWindow = 1024
	)

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.seqInit || engine != d.seqEngine {
		d.seqInit = complete
		d.seqEngine = engine
		d.lastSeq = seq + records
		d.seqLateRun = 0
		return
	}

	// lastSeq holds the sequence expected on the next message.
	switch diff := seq - d.lastSeq; {
	case diff == 0:
		// In order; only the base advances.
	case diff > ^uint32(0)-reorderWindow && d.seqLateRun < maxLateRun:
		d.seqLateRun++
		return
	case diff < forwardWindow:
		d.sequenceMissed.Add(uint64(diff))
	default:
		// A restart, which the counter does not span.
	}

	d.seqLateRun = 0
	d.seqInit = complete
	d.lastSeq = seq + records
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
}

// SamplerSnapshot is one rate a device declared for one named sampler.
type SamplerSnapshot struct {
	Exporter netip.Addr
	Version  flow.Version
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
		for sampler, entry := range table.rates {
			snapshots = append(snapshots, SamplerSnapshot{
				Exporter: key.exporter,
				Version:  key.proto,
				Sampler:  sampler,
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
			SamplingRate:       d.rateInForce(),
			SamplePool:         d.samplePool.Load(),
			SamplesDropped:     d.samplesDropped.Load(),
			PoolMeasured:       d.poolMeasured.Load(),
			DropsMeasured:      d.dropsMeasured.Load(),
		})
	}
	return snapshots
}
