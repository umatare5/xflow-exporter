// Package decoder turns received datagrams into normalized flow records.
// This file parses NetFlow v9 (RFC 3954), the template-driven format
// Flexible NetFlow and J-Flow v9 speak.
package decoder

import (
	"encoding/binary"
	"math"
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

		d.storeTemplate(key, templateID, &template{fields: fields}, issue)
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

// storeTemplate finishes compiling a template and registers it.
func (d *Decoder) storeTemplate(key domainKey, id uint16, t *template, issue func(reason string)) {
	recordLen := 0
	for _, f := range t.fields {
		recordLen += int(f.length)
	}
	// A record must fit a flowset alongside its header.
	if recordLen > 65535-flowSetHeaderLen {
		issue(ReasonInvalidTemplate)
		return
	}
	t.recordLen = recordLen

	if !d.templates.add(key, id, t) {
		// The domain is at its template bound; treat the announcement like an
		// invalid template so the loss is visible.
		issue(ReasonInvalidTemplate)
	}
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

		d.storeTemplate(key, templateID, &template{
			fields:     fields,
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
			d.readV9OptionsRecord(domain, tpl, record)
			continue
		}
		dst = appendV9Record(key, tpl, record, bootTime, domain, dst)
	}
	return dst
}

// readV9OptionsRecord extracts what this exporter consumes from one options
// record: the packet sampling rate, preferring the random-sampler interval
// over the plain one when both appear.
func (d *Decoder) readV9OptionsRecord(domain *domainState, tpl *template, record []byte) {
	var plain, random uint32

	offset := 0
	for i, f := range tpl.fields {
		value := record[offset : offset+int(f.length)]
		offset += int(f.length)
		if i < tpl.scopeCount {
			continue
		}

		switch f.fieldType {
		case fieldSamplingInterval:
			plain, _ = beUint32(value)
		case fieldSamplerRandomInterval:
			random, _ = beUint32(value)
		}
	}

	rate := random
	if rate == 0 {
		rate = plain
	}
	if rate > 0 {
		domain.samplingRate.Store(rate)
	}
}

// v9Times accumulates the flow clock fields of one record; the absolute
// clocks win over the uptime-relative pair when a template carries both.
type v9Times struct {
	firstUptimeMs, lastUptimeMs uint32
	hasUptime                   bool
	startAbs, endAbs            time.Time
}

// appendV9Record decodes one data record in place at the end of dst.
func appendV9Record(
	key domainKey, tpl *template, record []byte,
	bootTime time.Time, domain *domainState, dst []flow.Record,
) []flow.Record {
	dst = append(dst, flow.Record{
		Exporter: key.exporter,
		Version:  flow.VersionNetFlowV9,
		Flows:    1,
	})
	r := &dst[len(dst)-1]

	var times v9Times
	var outBytes, outPackets uint64

	offset := 0
	for _, f := range tpl.fields {
		value := record[offset : offset+int(f.length)]
		offset += int(f.length)
		applyV9Field(r, &times, &outBytes, &outPackets, f.fieldType, value)
	}

	// An egress-only template carries OUT_* alone; both present would double
	// the flow if summed, so IN_* wins.
	if r.Bytes == 0 {
		r.Bytes = outBytes
	}
	if r.Packets == 0 {
		r.Packets = outPackets
	}

	resolveV9Times(r, &times, bootTime)

	if r.SamplingRate == 0 {
		r.SamplingRate = domain.samplingRate.Load()
	}
	return dst
}

// resolveV9Times writes the flow instants, absolute clocks first.
func resolveV9Times(r *flow.Record, times *v9Times, bootTime time.Time) {
	switch {
	case !times.startAbs.IsZero() || !times.endAbs.IsZero():
		r.Start = times.startAbs
		r.End = times.endAbs
	case times.hasUptime:
		r.Start = bootTime.Add(time.Duration(times.firstUptimeMs) * time.Millisecond)
		r.End = bootTime.Add(time.Duration(times.lastUptimeMs) * time.Millisecond)
	}
}

// applyV9Field maps one field into the record. An unknown type is skipped by
// length, which is what lets a template carry fields this exporter does not
// model without desynchronizing the ones it does.
func applyV9Field(
	r *flow.Record, times *v9Times, outBytes, outPackets *uint64, fieldType uint16, value []byte,
) {
	switch fieldType {
	case fieldInBytes:
		r.Bytes, _ = beUint(value)
	case fieldInPackets:
		r.Packets, _ = beUint(value)
	case fieldOutBytes:
		*outBytes, _ = beUint(value)
	case fieldOutPackets:
		*outPackets, _ = beUint(value)
	case fieldProtocol:
		if v, ok := beUint8(value); ok {
			r.Protocol = v
		}
	case fieldSrcTOS:
		if v, ok := beUint8(value); ok {
			r.TOS = v
		}
	case fieldTCPFlags:
		if v, ok := beUint8(value); ok {
			r.TCPFlags = v
		}
	case fieldL4SrcPort:
		if v, ok := beUint16(value); ok {
			r.SrcPort = v
		}
	case fieldL4DstPort:
		if v, ok := beUint16(value); ok {
			r.DstPort = v
		}
	case fieldIPv4SrcAddr:
		if len(value) == ipv4Len {
			r.SrcAddr = netip.AddrFrom4([4]byte(value))
		}
	case fieldIPv4DstAddr:
		if len(value) == ipv4Len {
			r.DstAddr = netip.AddrFrom4([4]byte(value))
		}
	case fieldIPv6SrcAddr:
		if len(value) == ipv6Len {
			r.SrcAddr = netip.AddrFrom16([16]byte(value))
		}
	case fieldIPv6DstAddr:
		if len(value) == ipv6Len {
			r.DstAddr = netip.AddrFrom16([16]byte(value))
		}
	case fieldSrcMask, fieldIPv6SrcMask:
		if v, ok := beUint8(value); ok {
			r.SrcMask = v
		}
	case fieldDstMask, fieldIPv6DstMask:
		if v, ok := beUint8(value); ok {
			r.DstMask = v
		}
	case fieldInputSNMP:
		if v, ok := beUint32(value); ok {
			r.InputIf = v
		}
	case fieldOutputSNMP:
		if v, ok := beUint32(value); ok {
			r.OutputIf = v
		}
	case fieldSrcAS:
		if v, ok := beUint32(value); ok {
			r.SrcAS = v
		}
	case fieldDstAS:
		if v, ok := beUint32(value); ok {
			r.DstAS = v
		}
	default:
		applyV9TimeField(times, fieldType, value)
	}
}

// applyV9TimeField collects the flow clock fields.
func applyV9TimeField(times *v9Times, fieldType uint16, value []byte) {
	switch fieldType {
	case fieldFirstSwitched:
		times.firstUptimeMs, _ = beUint32(value)
		times.hasUptime = true
	case fieldLastSwitched:
		times.lastUptimeMs, _ = beUint32(value)
		times.hasUptime = true
	case fieldFlowStartSeconds:
		if at, ok := unixSeconds(value); ok {
			times.startAbs = at
		}
	case fieldFlowEndSeconds:
		if at, ok := unixSeconds(value); ok {
			times.endAbs = at
		}
	case fieldFlowStartMilliseconds:
		if at, ok := unixMilliseconds(value); ok {
			times.startAbs = at
		}
	case fieldFlowEndMilliseconds:
		if at, ok := unixMilliseconds(value); ok {
			times.endAbs = at
		}
	}
}

// beUint reads a big-endian unsigned integer of 1, 2, 4 or 8 bytes. Any other
// width reports false: the value cannot be represented, and guessing would
// publish a number the device did not send.
func beUint(value []byte) (uint64, bool) {
	switch len(value) {
	case 1:
		return uint64(value[0]), true
	case 2:
		return uint64(binary.BigEndian.Uint16(value)), true
	case 4:
		return uint64(binary.BigEndian.Uint32(value)), true
	case 8:
		return binary.BigEndian.Uint64(value), true
	default:
		return 0, false
	}
}

// The narrowing readers below report false for a value their target cannot
// hold: a four-byte protocol claiming 300 is garbage, and publishing a
// truncation of it would be a number the device did not send.

func beUint8(value []byte) (uint8, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxUint8 {
		return 0, false
	}
	return uint8(v), true
}

func beUint16(value []byte) (uint16, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxUint16 {
		return 0, false
	}
	return uint16(v), true
}

func beUint32(value []byte) (uint32, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxUint32 {
		return 0, false
	}
	return uint32(v), true
}

// unixSeconds and unixMilliseconds read an absolute flow clock. An epoch past
// the signed range is garbage rather than an instant.

func unixSeconds(value []byte) (time.Time, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0), true
}

func unixMilliseconds(value []byte) (time.Time, bool) {
	v, ok := beUint(value)
	if !ok || v > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(v)), true
}
