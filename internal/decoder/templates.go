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

// maxDomainsPerExporter bounds the observation domains one device may open.
// The Observation Domain ID is a wire field rather than a property of the
// fleet, so a device with a broken numbering scheme, or one under an
// attacker's control, would otherwise mint domains without end from a single
// permitted source address. A chassis exports one per linecard or VRF, so
// hundreds is already generous.
const maxDomainsPerExporter = 256

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

// domainState carries one observation domain's templates and the counters
// that are naturally per-domain rather than per-exporter.
type domainState struct {
	mu        sync.RWMutex
	templates map[uint16]*template

	// lastSeen is when a datagram last named this domain, which the idle
	// sweep reads to free the exporter's budget again.
	lastSeen atomic.Int64

	// sequence gap tracking. seqInit and lastSeq move under mu.
	seqInit bool
	lastSeq uint32
	// SequenceMissed counts export packets the sequence numbers say were
	// lost. Reordering and device restarts reset the base instead.
	sequenceMissed atomic.Uint64

	// samplingRate is the packet sampling rate the domain's options declared,
	// zero until one arrives.
	samplingRate atomic.Uint32
}

// templateStore indexes the per-domain state. Domains appear on first use,
// are bounded per exporter, and are swept once idle, so their count follows
// the fleet rather than the traffic.
type templateStore struct {
	mu      sync.RWMutex
	domains map[domainKey]*domainState
	// perExporter counts each device's live domains against its budget.
	perExporter map[netip.Addr]int

	// domainsRefused counts the datagrams the budget turned away, one per
	// datagram naming a domain past it, so the loss is visible rather than
	// silent.
	domainsRefused atomic.Uint64

	maxFields int
	ttl       time.Duration
	now       func() time.Time
}

// newTemplateStore creates a store enforcing the configured limits.
func newTemplateStore(cfg config.Parser) *templateStore {
	return &templateStore{
		domains:     make(map[domainKey]*domainState),
		perExporter: make(map[netip.Addr]int),
		maxFields:   cfg.MaxFieldsPerTemplate,
		ttl:         cfg.TemplateTTL,
		now:         time.Now,
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

	d = &domainState{templates: make(map[uint16]*template)}
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
	return evicted
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

// trackRecordSequence advances the IPFIX sequence, which counts data records
// rather than packets. When a message's own record count is unknown the
// tracking resets instead of guessing.
func (d *domainState) trackRecordSequence(seq, records uint32, complete bool) {
	const forwardWindow = 1 << 30

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.seqInit {
		d.seqInit = complete
		d.lastSeq = seq + records
		return
	}

	// lastSeq holds the sequence expected on the next message.
	if diff := seq - d.lastSeq; diff > 0 && diff < forwardWindow {
		d.sequenceMissed.Add(uint64(diff))
	}

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
	// SamplingRate is zero until the domain's options declared one.
	SamplingRate uint32
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
			Exporter:         key.exporter,
			ODID:             key.odid,
			Version:          key.proto,
			Templates:        data,
			OptionsTemplates: options,
			SequenceMissed:   d.sequenceMissed.Load(),
			SamplingRate:     d.samplingRate.Load(),
		})
	}
	return snapshots
}
