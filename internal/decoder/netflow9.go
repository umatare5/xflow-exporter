// Package decoder turns received datagrams into normalized flow records.
// This file parses NetFlow v9 (RFC 3954), the template-driven format
// Flexible NetFlow and J-Flow v9 speak.
package decoder

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

const (
	netflowV9HeaderLen = 20
	// flowSetHeaderLen is the id and length every flowset starts with.
	flowSetHeaderLen = 4
	// Reserved flowset ids. 0 announces templates, 1 options templates, and
	// data flowsets start at minDataSetID.
	templateFlowSetID        = 0
	optionsTemplateFlowSetID = 1
	minDataSetID             = 256
)

// The v9 field types this exporter maps into flow.Record. Every other type is
// skipped over by its declared length. Numbers are RFC 3954 / IANA.
const (
	fieldInBytes       = 1
	fieldInPackets     = 2
	fieldProtocol      = 4
	fieldSrcTOS        = 5
	fieldTCPFlags      = 6
	fieldL4SrcPort     = 7
	fieldIPv4SrcAddr   = 8
	fieldSrcMask       = 9
	fieldInputSNMP     = 10
	fieldL4DstPort     = 11
	fieldIPv4DstAddr   = 12
	fieldDstMask       = 13
	fieldOutputSNMP    = 14
	fieldSrcAS         = 16
	fieldDstAS         = 17
	fieldLastSwitched  = 21
	fieldFirstSwitched = 22
	fieldOutBytes      = 23
	fieldOutPackets    = 24
	fieldIPv6SrcAddr   = 27
	fieldIPv6DstAddr   = 28
	fieldIPv6SrcMask   = 29
	fieldIPv6DstMask   = 30

	// Absolute flow clocks some Flexible NetFlow templates export instead of
	// the uptime-relative pair above.
	fieldFlowStartSeconds      = 150
	fieldFlowEndSeconds        = 151
	fieldFlowStartMilliseconds = 152
	fieldFlowEndMilliseconds   = 153

	// Options fields carrying the packet sampling configuration.
	fieldSamplingInterval      = 34
	fieldSamplerRandomInterval = 50
)

// ipv4Len and ipv6Len guard the address field reads.
const (
	ipv4Len = 4
	ipv6Len = 16
)

// decodeNetFlowV9 parses one v9 datagram. Per-flowset problems are counted
// through issue and do not fail the datagram: a missing template must not
// discard the flowsets whose templates are known.
func (d *Decoder) decodeNetFlowV9(
	exporter netip.Addr, payload []byte, dst []flow.Record, issue func(reason string),
) ([]flow.Record, *decodeError) {
	if len(payload) < netflowV9HeaderLen {
		return dst, malformed("v9 header needs %d bytes, datagram has %d", netflowV9HeaderLen, len(payload))
	}

	sysUptimeMs := binary.BigEndian.Uint32(payload[4:8])
	exportSecs := binary.BigEndian.Uint32(payload[8:12])
	sequence := binary.BigEndian.Uint32(payload[12:16])
	key := domainKey{exporter: exporter, odid: binary.BigEndian.Uint32(payload[16:20])}

	domain := d.templates.domain(key)
	if domain == nil {
		issue(ReasonDomainLimit)
		return dst, nil
	}
	domain.trackSequence(sequence)

	bootTime := time.Unix(int64(exportSecs), 0).Add(-time.Duration(sysUptimeMs) * time.Millisecond)

	offset := netflowV9HeaderLen
	for offset+flowSetHeaderLen <= len(payload) {
		setID := binary.BigEndian.Uint16(payload[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		if setLen < flowSetHeaderLen {
			return dst, malformed("v9 flowset %d declares length %d, below the %d-byte flowset header",
				setID, setLen, flowSetHeaderLen)
		}
		if offset+setLen > len(payload) {
			return dst, malformed("v9 flowset %d of %d bytes runs past the datagram", setID, setLen)
		}

		set := payload[offset+flowSetHeaderLen : offset+setLen]
		dst = d.decodeV9FlowSet(key, domain, setID, set, bootTime, dst, issue)
		offset += setLen
	}

	// Trailing bytes shorter than a flowset header are padding, tolerated.
	return dst, nil
}

// decodeV9FlowSet routes one flowset by its id.
func (d *Decoder) decodeV9FlowSet(
	key domainKey, domain *domainState, setID uint16, set []byte,
	bootTime time.Time, dst []flow.Record, issue func(reason string),
) []flow.Record {
	switch {
	case setID == templateFlowSetID:
		d.parseV9Templates(key, set, issue)
	case setID == optionsTemplateFlowSetID:
		d.parseV9OptionsTemplates(key, set, issue)
	case setID >= minDataSetID:
		dst = d.decodeV9DataSet(key, domain, setID, set, bootTime, dst, issue)
	default:
		// 2-255 are reserved. A device using one speaks a dialect this
		// exporter does not, which must be visible rather than skipped.
		issue(ReasonReservedSet)
	}
	return dst
}

// parseV9Templates compiles every template in one template flowset. A broken
// specifier desynchronizes the rest of the flowset, so parsing stops at the
// first invalid template.
func (d *Decoder) parseV9Templates(key domainKey, set []byte, issue func(reason string)) {
	offset := 0
	for offset+flowSetHeaderLen <= len(set) {
		templateID := binary.BigEndian.Uint16(set[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(set[offset+2 : offset+4]))
		offset += flowSetHeaderLen

		fields, next, ok := d.parseV9FieldSpecs(set, offset, templateID, fieldCount, issue)
		if !ok {
			return
		}
		offset = next

		d.registerTemplate(key, templateID,
			&template{fields: fields, recordLen: fixedRecordLen(fields)}, issue)
	}
}

// parseV9FieldSpecs validates one template head and reads its field
// specifiers, returning the offset past them.
func (d *Decoder) parseV9FieldSpecs(
	set []byte, offset int, templateID uint16, fieldCount int, issue func(reason string),
) (fields []templateField, next int, ok bool) {
	const specLen = 4

	if templateID < minDataSetID {
		issue(ReasonInvalidTemplate)
		return nil, 0, false
	}
	if fieldCount < 1 || fieldCount > d.templates.maxFields {
		issue(ReasonInvalidTemplate)
		return nil, 0, false
	}
	if offset+fieldCount*specLen > len(set) {
		issue(ReasonInvalidTemplate)
		return nil, 0, false
	}

	fields = make([]templateField, fieldCount)
	for i := range fieldCount {
		spec := set[offset+i*specLen:]
		fields[i] = templateField{
			fieldType: binary.BigEndian.Uint16(spec[0:2]),
			length:    binary.BigEndian.Uint16(spec[2:4]),
		}
		// A zero-width field would let a record decode forever without
		// consuming input; v9 has no variable-length encoding to excuse it.
		if fields[i].length == 0 {
			issue(ReasonInvalidTemplate)
			return nil, 0, false
		}
	}

	return fields, offset + fieldCount*specLen, true
}

// registerTemplate checks a compiled template's record length and registers
// it. The caller has computed recordLen, fixed or minimum.
func (d *Decoder) registerTemplate(key domainKey, id uint16, t *template, issue func(reason string)) {
	// A record must fit a set alongside its header.
	if t.recordLen > 65535-flowSetHeaderLen {
		issue(ReasonInvalidTemplate)
		return
	}

	if !d.templates.add(key, id, t) {
		// The domain is at its template bound; treat the announcement like an
		// invalid template so the loss is visible.
		issue(ReasonInvalidTemplate)
	}
}

// fixedRecordLen sums a fixed-length field set.
func fixedRecordLen(fields []templateField) int {
	recordLen := 0
	for _, f := range fields {
		recordLen += int(f.length)
	}
	return recordLen
}

// parseV9OptionsTemplates compiles every options template in one flowset.
// The scope and option lengths are byte lengths of the specifier sections.
func (d *Decoder) parseV9OptionsTemplates(key domainKey, set []byte, issue func(reason string)) {
	const (
		headLen = 6
		specLen = 4
	)

	offset := 0
	for offset+headLen <= len(set) {
		templateID := binary.BigEndian.Uint16(set[offset : offset+2])
		scopeBytes := int(binary.BigEndian.Uint16(set[offset+2 : offset+4]))
		optionBytes := int(binary.BigEndian.Uint16(set[offset+4 : offset+6]))
		offset += headLen

		if templateID < minDataSetID || scopeBytes%specLen != 0 || optionBytes%specLen != 0 {
			issue(ReasonInvalidTemplate)
			return
		}
		scopeCount := scopeBytes / specLen
		optionCount := optionBytes / specLen
		fieldCount := scopeCount + optionCount
		if fieldCount < 1 || fieldCount > d.templates.maxFields {
			issue(ReasonInvalidTemplate)
			return
		}
		if offset+fieldCount*specLen > len(set) {
			issue(ReasonInvalidTemplate)
			return
		}

		fields := make([]templateField, fieldCount)
		for i := range fieldCount {
			spec := set[offset+i*specLen:]
			fields[i] = templateField{
				fieldType: binary.BigEndian.Uint16(spec[0:2]),
				length:    binary.BigEndian.Uint16(spec[2:4]),
			}
			// A zero-length scope is seen in the wild (a bare system scope);
			// a zero-length option field would decode without consuming.
			if fields[i].length == 0 && i >= scopeCount {
				issue(ReasonInvalidTemplate)
				return
			}
		}
		offset += fieldCount * specLen

		d.registerTemplate(key, templateID, &template{
			fields:     fields,
			recordLen:  fixedRecordLen(fields),
			scopeCount: scopeCount,
			options:    true,
		}, issue)
	}
}

// decodeV9DataSet decodes one data flowset against its template. Leftover
// bytes shorter than one record are the padding some devices append.
func (d *Decoder) decodeV9DataSet(
	key domainKey, domain *domainState, setID uint16, set []byte,
	bootTime time.Time, dst []flow.Record, issue func(reason string),
) []flow.Record {
	tpl, ok := d.templates.lookup(key, setID)
	if !ok {
		// Expected after a restart until the device re-announces; the counter
		// makes a device that never does visible.
		issue(ReasonMissingTemplate)
		return dst
	}

	count := len(set) / tpl.recordLen
	if count == 0 {
		issue(ReasonMalformed)
		return dst
	}

	for i := range count {
		record := set[i*tpl.recordLen : (i+1)*tpl.recordLen]
		if tpl.options {
			d.readV9OptionsRecord(key.exporter, domain, tpl, record)
			continue
		}
		dst = d.appendV9Record(key, tpl, record, bootTime, domain, dst)
	}
	return dst
}

// readV9OptionsRecord walks one fixed-length options record and feeds the
// shared options consumer.
func (d *Decoder) readV9OptionsRecord(exporter netip.Addr, domain *domainState, tpl *template, record []byte) {
	var opts optionsState

	offset := 0
	for i, f := range tpl.fields {
		value := record[offset : offset+int(f.length)]
		offset += int(f.length)
		if i < tpl.scopeCount {
			continue
		}
		opts.apply(f.fieldType, f.enterprise, value)
	}

	opts.commit(d, exporter, domain)
}

// appendV9Record decodes one data record in place at the end of dst.
func (d *Decoder) appendV9Record(
	key domainKey, tpl *template, record []byte,
	bootTime time.Time, domain *domainState, dst []flow.Record,
) []flow.Record {
	dst = append(dst, flow.Record{
		Exporter: key.exporter,
		Version:  flow.VersionNetFlowV9,
		Flows:    1,
	})
	r := &dst[len(dst)-1]

	state := fieldState{intern: d.strings}

	offset := 0
	for _, f := range tpl.fields {
		value := record[offset : offset+int(f.length)]
		offset += int(f.length)
		applyField(r, &state, f.fieldType, f.enterprise, value)
	}

	finishRecord(r, &state, bootTime, domain)
	d.resolveApplication(key.exporter, r)
	return dst
}
