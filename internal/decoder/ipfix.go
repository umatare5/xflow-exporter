// This file parses IPFIX (RFC 7011), NetFlow v10 in the version field.

package decoder

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	ipfixHeaderLen = 16
	// IPFIX set ids: 2 announces templates, 3 options templates, and data
	// sets start at minDataSetID like v9; 0-1 are unused and 4-255 reserved.
	ipfixTemplateSetID        = 2
	ipfixOptionsTemplateSetID = 3
	// variableFieldLength marks an IPFIX variable-length field, whose actual
	// length travels in each record.
	variableFieldLength = 65535
	// enterpriseBit on a field type says a four-byte enterprise number
	// follows the specifier.
	enterpriseBit = 0x8000
)

// decodeIPFIX parses one IPFIX message. Like v9, per-set problems are counted
// through issue without failing the message.
func (d *Decoder) decodeIPFIX(
	exporter netip.Addr, payload []byte, dst []flow.Record, issue func(reason string),
) ([]flow.Record, *decodeError) {
	if len(payload) < ipfixHeaderLen {
		return dst, malformed("ipfix header needs %d bytes, datagram has %d", ipfixHeaderLen, len(payload))
	}

	msgLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if msgLen < ipfixHeaderLen || msgLen > len(payload) {
		return dst, malformed("ipfix message length %d does not fit the %d-byte datagram", msgLen, len(payload))
	}

	sequence := binary.BigEndian.Uint32(payload[8:12])
	key := domainKey{exporter: exporter, odid: binary.BigEndian.Uint32(payload[12:16]), proto: flow.VersionIPFIX}
	domain := d.templates.domain(key)
	if domain == nil {
		issue(ReasonDomainLimit)
		return dst, nil
	}

	dataRecords, complete := 0, true

	offset := ipfixHeaderLen
	for offset+flowSetHeaderLen <= msgLen {
		setID := binary.BigEndian.Uint16(payload[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		if setLen < flowSetHeaderLen {
			return dst, malformed("ipfix set %d declares length %d, below the %d-byte set header",
				setID, setLen, flowSetHeaderLen)
		}
		if offset+setLen > msgLen {
			return dst, malformed("ipfix set %d of %d bytes runs past the message", setID, setLen)
		}

		set := payload[offset+flowSetHeaderLen : offset+setLen]
		var records int
		dst, records, complete = d.decodeIPFIXSet(key, domain, setID, set, dst, complete, issue)
		dataRecords += records
		offset += setLen
	}

	// The sequence number counts data records, so a message with an
	// undecodable set leaves the true count unknown and resets the tracking.
	domain.trackRecordSequence(sequence, uint32(dataRecords), complete) //nolint:gosec // Bounded by message size.
	return dst, nil
}

// decodeIPFIXSet routes one set by its id, reporting how many data records it
// held and whether that count is trustworthy.
func (d *Decoder) decodeIPFIXSet(
	key domainKey, domain *domainState, setID uint16, set []byte,
	dst []flow.Record, complete bool, issue func(reason string),
) ([]flow.Record, int, bool) {
	switch {
	case setID == ipfixTemplateSetID:
		d.parseIPFIXTemplates(key, set, issue)
		return dst, 0, complete
	case setID == ipfixOptionsTemplateSetID:
		d.parseIPFIXOptionsTemplates(key, set, issue)
		return dst, 0, complete
	case setID >= minDataSetID:
		return d.decodeIPFIXDataSet(key, domain, setID, set, dst, complete, issue)
	default:
		issue(ReasonReservedSet)
		return dst, 0, false
	}
}

// parseIPFIXTemplates compiles every template in one template set. A field
// count of zero is a withdrawal rather than an announcement.
func (d *Decoder) parseIPFIXTemplates(key domainKey, set []byte, issue func(reason string)) {
	offset := 0
	for offset+flowSetHeaderLen <= len(set) {
		templateID := binary.BigEndian.Uint16(set[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(set[offset+2 : offset+4]))
		offset += flowSetHeaderLen

		if fieldCount == 0 {
			d.withdrawTemplates(key, templateID, false)
			continue
		}
		if templateID < minDataSetID || fieldCount > d.templates.maxFields {
			issue(ReasonInvalidTemplate)
			return
		}

		fields, minLen, hasVariable, next, ok := parseIPFIXFieldSpecs(set, offset, fieldCount)
		if !ok {
			issue(ReasonInvalidTemplate)
			return
		}
		offset = next

		d.registerTemplate(key, templateID, &template{
			fields:      fields,
			recordLen:   minLen,
			hasVariable: hasVariable,
		}, issue)
	}
}

// parseIPFIXOptionsTemplates compiles every options template in one set. The
// head differs from v9: a total field count and a scope field count.
func (d *Decoder) parseIPFIXOptionsTemplates(key domainKey, set []byte, issue func(reason string)) {
	// RFC 7011 figures T and V put no scope field count on a withdrawal, so
	// it is the template id and a field count of zero and nothing else. An
	// all-options withdrawal is therefore a set of length 8, whose body falls
	// short of an announcement's head.
	const (
		headLen       = 6
		withdrawalLen = 4
	)

	offset := 0
	for offset+withdrawalLen <= len(set) {
		templateID := binary.BigEndian.Uint16(set[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(set[offset+2 : offset+4]))

		if fieldCount == 0 {
			d.withdrawTemplates(key, templateID, true)
			offset += withdrawalLen
			continue
		}

		if offset+headLen > len(set) {
			return
		}
		scopeCount := int(binary.BigEndian.Uint16(set[offset+4 : offset+6]))
		offset += headLen

		// RFC 7011 requires at least one scope field, and the scope fields
		// are a prefix of the field list.
		if templateID < minDataSetID || scopeCount < 1 || scopeCount > fieldCount ||
			fieldCount > d.templates.maxFields {
			issue(ReasonInvalidTemplate)
			return
		}

		fields, minLen, hasVariable, next, ok := parseIPFIXFieldSpecs(set, offset, fieldCount)
		if !ok {
			issue(ReasonInvalidTemplate)
			return
		}
		offset = next

		d.registerTemplate(key, templateID, &template{
			fields:      fields,
			recordLen:   minLen,
			hasVariable: hasVariable,
			scopeCount:  scopeCount,
			options:     true,
		}, issue)
	}
}

// withdrawTemplates handles an IPFIX withdrawal: one template, or every
// template of a kind when the withdrawn id names the set id itself.
func (d *Decoder) withdrawTemplates(key domainKey, templateID uint16, options bool) {
	switch templateID {
	case ipfixTemplateSetID, ipfixOptionsTemplateSetID:
		d.templates.removeAll(key, templateID == ipfixOptionsTemplateSetID)
	default:
		_ = options
		d.templates.remove(key, templateID)
	}
}

// parseIPFIXFieldSpecs reads fieldCount specifiers, each four bytes plus a
// four-byte enterprise number when the type carries the enterprise bit. A
// zero-width fixed field is refused; the variable marker contributes one byte
// to the minimum record length.
func parseIPFIXFieldSpecs(
	set []byte, offset, fieldCount int,
) (fields []templateField, minLen int, hasVariable bool, next int, ok bool) {
	const (
		specLen       = 4
		enterpriseLen = 4
	)

	fields = make([]templateField, 0, fieldCount)
	for range fieldCount {
		if offset+specLen > len(set) {
			return nil, 0, false, 0, false
		}

		fieldType := binary.BigEndian.Uint16(set[offset : offset+2])
		length := binary.BigEndian.Uint16(set[offset+2 : offset+4])
		offset += specLen

		var enterprise uint32
		if fieldType&enterpriseBit != 0 {
			if offset+enterpriseLen > len(set) {
				return nil, 0, false, 0, false
			}
			enterprise = binary.BigEndian.Uint32(set[offset : offset+enterpriseLen])
			fieldType &^= enterpriseBit
			offset += enterpriseLen
		}

		switch length {
		case variableFieldLength:
			hasVariable = true
			minLen++
		case 0:
			return nil, 0, false, 0, false
		default:
			minLen += int(length)
		}

		fields = append(fields, templateField{fieldType: fieldType, length: length, enterprise: enterprise})
	}

	return fields, minLen, hasVariable, offset, true
}

// decodeIPFIXDataSet decodes one data set. With a variable-length template
// the record boundaries come from the records themselves, so a walk failure
// abandons the rest of the set rather than guessing an offset.
func (d *Decoder) decodeIPFIXDataSet(
	key domainKey, domain *domainState, setID uint16, set []byte,
	dst []flow.Record, complete bool, issue func(reason string),
) ([]flow.Record, int, bool) {
	tpl, ok := d.templates.lookup(key, setID)
	if !ok {
		issue(ReasonMissingTemplate)
		return dst, 0, false
	}

	records := 0
	offset := 0
	for len(set)-offset >= tpl.recordLen {
		var walked bool
		dst, offset, walked = d.decodeIPFIXRecord(key, domain, tpl, set, offset, dst)
		if !walked {
			issue(ReasonMalformed)
			return dst, records, false
		}
		records++
	}
	// Leftover bytes shorter than a minimum record are padding, tolerated.
	return dst, records, complete
}

// decodeIPFIXRecord walks one record, flow or options, returning the offset
// past it.
func (d *Decoder) decodeIPFIXRecord(
	key domainKey, domain *domainState, tpl *template, set []byte, offset int,
	dst []flow.Record,
) ([]flow.Record, int, bool) {
	if tpl.options {
		next, ok := d.readIPFIXOptionsRecord(key.exporter, domain, tpl, set, offset)
		return dst, next, ok
	}

	dst = append(dst, flow.Record{
		Exporter: key.exporter,
		Version:  flow.VersionIPFIX,
		Flows:    1,
	})
	r := &dst[len(dst)-1]
	state := fieldState{intern: d.strings}

	for _, f := range tpl.fields {
		value, next, ok := nextFieldValue(f, set, offset)
		if !ok {
			return dst[:len(dst)-1], 0, false
		}
		offset = next
		applyField(r, &state, f.fieldType, f.enterprise, value)
	}

	// IPFIX has no uptime anchor in its header, so uptime-relative clocks
	// are left absent unless a future element supplies the boot instant.
	finishRecord(r, &state, time.Time{}, domain)
	d.resolveApplication(key.exporter, r)
	return dst, offset, true
}

// readIPFIXOptionsRecord walks one options record into the shared consumer.
func (d *Decoder) readIPFIXOptionsRecord(
	exporter netip.Addr, domain *domainState, tpl *template, set []byte, offset int,
) (int, bool) {
	var opts optionsState

	for _, f := range tpl.fields {
		value, next, ok := nextFieldValue(f, set, offset)
		if !ok {
			return 0, false
		}
		offset = next
		opts.apply(f.fieldType, f.enterprise, value)
	}

	opts.commit(d, exporter, domain)
	return offset, true
}

// nextFieldValue returns one field's value at set[offset:], decoding the
// variable-length prefix where the template declares one.
func nextFieldValue(f templateField, set []byte, offset int) (value []byte, next int, ok bool) {
	if f.length != variableFieldLength {
		end := offset + int(f.length)
		if end > len(set) {
			return nil, 0, false
		}
		return set[offset:end], end, true
	}

	// One length byte, or 255 followed by a two-byte length for a longer
	// value. Either way the declared bytes must fit the set.
	if offset >= len(set) {
		return nil, 0, false
	}
	short := int(set[offset])
	offset++
	length := short
	if short == 255 {
		if offset+2 > len(set) {
			return nil, 0, false
		}
		length = int(binary.BigEndian.Uint16(set[offset : offset+2]))
		offset += 2
	}

	end := offset + length
	if end > len(set) {
		return nil, 0, false
	}
	return set[offset:end], end, true
}
