// Package decoder turns received datagrams into normalized flow records.
// This file holds the template store NetFlow v9 and IPFIX decoding depends
// on, and the per-domain state that travels with it.
package decoder

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// maxTemplatesPerDomain bounds one observation domain against a device, or an
// attacker, registering templates without end. Real devices carry tens.
const maxTemplatesPerDomain = 8192

// templateField is one field specifier of a template. Enterprise is zero for
// an IANA information element and the enterprise number for a vendor one,
// which only IPFIX can express. An IPFIX variable-length field carries length
// 65535 and encodes each value's length in the record itself.
type templateField struct {
	fieldType  uint16
	length     uint16
	enterprise uint32
}

// template is one compiled template. Fields are immutable after compilation;
// refreshedAt moves under the domain lock on every re-announcement.
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
type domainKey struct {
	exporter netip.Addr
	odid     uint32
}

// domainState carries one observation domain's templates and the counters
// that are naturally per-domain rather than per-exporter.
type domainState struct {
	mu        sync.RWMutex
	templates map[uint16]*template

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

// templateStore indexes the per-domain state. Domains appear on first use and
// are never removed: their count is bounded by the fleet, not by traffic.
type templateStore struct {
	mu      sync.RWMutex
	domains map[domainKey]*domainState

	maxFields int
	ttl       time.Duration
	now       func() time.Time
}

// newTemplateStore creates a store enforcing the configured limits.
func newTemplateStore(cfg config.Parser) *templateStore {
	return &templateStore{
		domains:   make(map[domainKey]*domainState),
		maxFields: cfg.MaxFieldsPerTemplate,
		ttl:       cfg.TemplateTTL,
		now:       time.Now,
	}
}

// domain returns one observation domain's state, creating it on first use.
func (s *templateStore) domain(key domainKey) *domainState {
	s.mu.RLock()
	d, ok := s.domains[key]
	s.mu.RUnlock()
	if ok {
		return d
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.domains[key]; ok {
		return d
	}
	d = &domainState{templates: make(map[uint16]*template)}
	s.domains[key] = d
	return d
}

// add registers or refreshes one template. A full domain drops expired
// templates first and rejects the addition when nothing expired.
func (s *templateStore) add(key domainKey, id uint16, t *template) bool {
	d := s.domain(key)
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
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.templates, id)
}

// removeAll withdraws every template of one kind in the domain.
func (s *templateStore) removeAll(key domainKey, options bool) {
	d := s.domain(key)
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

// DomainSnapshot is one observation domain's state at one instant.
type DomainSnapshot struct {
	Exporter         netip.Addr
	ODID             uint32
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
			Templates:        data,
			OptionsTemplates: options,
			SequenceMissed:   d.sequenceMissed.Load(),
			SamplingRate:     d.samplingRate.Load(),
		})
	}
	return snapshots
}
