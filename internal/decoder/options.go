// This file consumes options records: the sampling configuration and the
// Cisco AVC application tables both protocols announce through them.

package decoder

// IPFIX PSAMP sampling elements, alongside the legacy v9 pair declared with
// the field constants.
const (
	// The Selector a record was chosen by, which PSAMP numbers within the
	// observation domain and uses where v9 uses the samplerId.
	fieldSelectorID             = 302
	fieldSamplingPacketInterval = 305
	fieldSamplingPacketSpace    = 306
	// The random n-out-of-N sampler pair: size packets selected out of each
	// population.
	fieldSamplingSize       = 309
	fieldSamplingPopulation = 310
)

// The scopes that tie a declaration to less than the device. The v9 scope
// types are RFC 3954 section 6.1's own numbering, which overlaps the field
// types, so only a field's position marks it a scope; IPFIX names each scope
// by its element.
const (
	v9ScopeInterface         = 2
	v9ScopeTemplate          = 5
	fieldTemplateID          = 145
	fieldObservationDomainID = 149
)

// unsampledSamplerID is the samplerId Cisco gives a cache it does not sample.
// The value is an ordinary identifier to RFC 5477 and to IANA, so it carries
// the convention only until a device declares a rate for it.
const unsampledSamplerID = 0

// AVC application name element; the identifier is fieldApplicationID.
const fieldApplicationName = 96

// optionsState accumulates one options record's values, committed once the
// record is fully read.
type optionsState struct {
	samplerID    uint32
	hasSamplerID bool
	// selectorID is PSAMP's identifier for the same declaration, scoped to
	// the observation domain rather than the device.
	selectorID    uint32
	hasSelectorID bool

	plainInterval  uint32
	randomInterval uint32
	packetInterval uint32
	packetSpace    uint32
	hasSpace       bool
	samplingSize   uint32
	population     uint32

	appID       uint32
	appName     []byte
	appCategory []byte

	// The scope fields a declaration can be tied to, each flagged on its own.
	scopeTemplate     uint16
	hasScopeTemplate  bool
	scopeInterface    uint32
	hasScopeInterface bool
	scopeDomain       uint32
	hasScopeDomain    bool
}

// apply captures one field this exporter consumes, scope or not, and reports
// as applyField does. RFC 6759 scopes the application name and attribute
// mappings on applicationId, so the field naming what a record describes is
// in the scope area: skipping it left the table empty on every Cisco AVC
// export. Nothing else consumed here is an identifier a template scopes on.
func (o *optionsState) apply(fieldType uint16, enterprise uint32, value []byte) bool {
	if enterprise == ciscoPEN && fieldType == fieldCiscoAppCategory {
		o.appCategory = value
		return true
	}
	if enterprise != 0 {
		return false
	}

	switch fieldType {
	case fieldSamplerID:
		o.samplerID, o.hasSamplerID = beUint32(value)
	case fieldSelectorID:
		o.selectorID, o.hasSelectorID = beUint32(value)
	case fieldSamplingInterval:
		o.plainInterval, _ = beUint32(value)
	case fieldSamplerRandomInterval:
		o.randomInterval, _ = beUint32(value)
	case fieldSamplingPacketInterval:
		o.packetInterval, _ = beUint32(value)
	case fieldSamplingPacketSpace:
		o.packetSpace, _ = beUint32(value)
		o.hasSpace = true
	case fieldSamplingSize:
		o.samplingSize, _ = beUint32(value)
	case fieldSamplingPopulation:
		o.population, _ = beUint32(value)
	case fieldApplicationID:
		o.appID, _ = beUint32(value)
	case fieldApplicationName:
		o.appName = value
	default:
		return false
	}
	return true
}

// applyV9Scope captures one v9 scope field.
func (o *optionsState) applyV9Scope(scopeType uint16, value []byte) {
	switch scopeType {
	case v9ScopeTemplate:
		o.scopeTemplate, o.hasScopeTemplate = beUint16(value)
	case v9ScopeInterface:
		o.scopeInterface, o.hasScopeInterface = beUint32(value)
	}
}

// applyIPFIXScope captures one IPFIX scope field and reports as applyField
// does.
func (o *optionsState) applyIPFIXScope(fieldType uint16, enterprise uint32, value []byte) bool {
	if enterprise != 0 {
		return false
	}

	switch fieldType {
	case fieldTemplateID:
		o.scopeTemplate, o.hasScopeTemplate = beUint16(value)
	case fieldInputSNMP:
		o.scopeInterface, o.hasScopeInterface = beUint32(value)
	case fieldObservationDomainID:
		o.scopeDomain, o.hasScopeDomain = beUint32(value)
	default:
		return false
	}
	return true
}

// commit publishes what the record declared: the sampling rate onto the
// device's sampler table, and the application strings into its application
// table. A declaration naming no sampler lands on the first scope it carries
// of template, interface and another domain, and on its own domain where it
// carries none of them.
func (o *optionsState) commit(d *Decoder, key domainKey, port uint16, domain *domainState) {
	if rate := o.samplingRate(); rate > 0 {
		id, named := o.declaredID()
		switch {
		case named:
			d.templates.declareSampler(domain, key.odid, id, named, rate)
		case o.hasScopeTemplate:
			d.templates.declareScoped(domain, scopedRef{
				kind: scopeTemplate, odid: key.odid, port: port, value: uint32(o.scopeTemplate),
			}, rate)
		case o.hasScopeInterface:
			d.templates.declareScoped(domain, scopedRef{
				kind: scopeInterface, odid: key.odid, value: o.scopeInterface,
			}, rate)
		case o.hasScopeDomain && o.scopeDomain != key.odid:
			d.templates.declareScoped(domain, scopedRef{kind: scopeDomain, value: o.scopeDomain}, rate)
		default:
			domain.samplingRate.Store(rate)
			d.templates.declareSampler(domain, key.odid, id, named, rate)
		}
	}

	if o.appID != 0 {
		// The announcement instant comes from the template clock, which is
		// the one the sweep measures its cutoff against.
		at := d.templates.now().UnixNano()
		if len(o.appName) > 0 {
			d.apps.setName(key.exporter, o.appID, o.appName, at)
		}
		if len(o.appCategory) > 0 {
			d.apps.setCategory(key.exporter, o.appID, o.appCategory, at)
		}
	}
}

// declaredID returns the identifier this declaration is tied to. A record
// carrying both elements is taken at its samplerId, the element the rest of
// the device's exports name their selection process by.
func (o *optionsState) declaredID() (id uint32, named bool) {
	switch {
	case o.hasSamplerID:
		return o.samplerID, true
	case o.hasSelectorID:
		return o.selectorID, true
	default:
		return 0, false
	}
}

// samplingRate resolves the declared fields into one 1-in-N rate. The PSAMP
// pair is the modern spelling: N packets selected then M skipped means one
// selected stretch every interval+space packets. The random sampler declares
// size selected out of each population instead.
func (o *optionsState) samplingRate() uint32 {
	if o.hasSpace && o.packetInterval > 0 {
		return (o.packetInterval + o.packetSpace) / o.packetInterval
	}
	if o.samplingSize > 0 && o.population > 0 {
		return o.population / o.samplingSize
	}
	if o.randomInterval > 0 {
		return o.randomInterval
	}
	return o.plainInterval
}
