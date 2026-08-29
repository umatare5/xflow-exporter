// This file consumes options records: the sampling configuration and the
// Cisco AVC application tables both protocols announce through them.

package decoder

import (
	"net/netip"
)

// IPFIX PSAMP sampling elements, alongside the legacy v9 pair declared with
// the field constants.
const (
	fieldSamplingPacketInterval = 305
	fieldSamplingPacketSpace    = 306
	// The random n-out-of-N sampler pair NetFlow-Lite exports: size packets
	// selected out of each population.
	fieldSamplingSize       = 309
	fieldSamplingPopulation = 310
)

// AVC application name element; the identifier is fieldApplicationID.
const fieldApplicationName = 96

// optionsState accumulates one options record's values, committed once the
// record is fully read.
type optionsState struct {
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
}

// apply captures one field this exporter consumes, scope or not. RFC 6759
// scopes the application name and attribute mappings on applicationId, so the
// field naming what a record describes is in the scope area: skipping it left
// the table empty on every Cisco AVC export. Nothing else consumed here is an
// identifier a template scopes on.
func (o *optionsState) apply(fieldType uint16, enterprise uint32, value []byte) {
	if enterprise == ciscoPEN {
		if fieldType == fieldCiscoAppCategory {
			o.appCategory = value
		}
		return
	}
	if enterprise != 0 {
		return
	}

	switch fieldType {
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
	}
}

// commit publishes what the record declared: the sampling rate onto the
// domain, and the application strings into the exporter's table.
func (o *optionsState) commit(d *Decoder, exporter netip.Addr, domain *domainState) {
	if rate := o.samplingRate(); rate > 0 {
		domain.samplingRate.Store(rate)
	}

	if o.appID != 0 {
		if len(o.appName) > 0 {
			d.apps.setName(exporter, o.appID, o.appName)
		}
		if len(o.appCategory) > 0 {
			d.apps.setCategory(exporter, o.appID, o.appCategory)
		}
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
