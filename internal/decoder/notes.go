// This file names the template elements no reader consumes, which RFC 7011
// section 9 requires a collector to note.

package decoder

import (
	"strconv"
	"sync"
	"time"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// maxNotesPerMinute bounds the log lines naming unread elements. A layout
// earns one when it arrives or changes, and a forged sender can change one
// with every datagram.
const maxNotesPerMinute = 60

// noteLimiter admits up to maxNotesPerMinute notes a minute and counts the
// ones it withholds.
type noteLimiter struct {
	mu         sync.Mutex
	minute     int64
	sent       int
	suppressed int
}

// admit reports whether a note fits the current minute and, when one does,
// how many were withheld since the last one admitted.
func (l *noteLimiter) admit(now time.Time) (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if minute := now.Unix() / 60; minute != l.minute {
		l.minute, l.sent = minute, 0
	}
	if l.sent == maxNotesPerMinute {
		l.suppressed++
		return false, 0
	}
	l.sent++
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
}

// noteUnread logs the elements of t no reader consumes, and reports whether
// the layout is settled: it carries none, or its line was written. A line the
// limit withholds allocates nothing, and leaves the next refresh to ask again.
func (d *Decoder) noteUnread(key domainKey, port, id uint16, t *template) bool {
	first := d.nextUnread(key.proto, t, 0)
	if first < 0 {
		return true
	}
	ok, suppressed := d.notes.admit(d.now())
	if !ok {
		return false
	}
	var unread []string
	for i := first; i >= 0; i = d.nextUnread(key.proto, t, i+1) {
		unread = append(unread, elementName(t.fields[i]))
	}
	d.logger.Info("Template carries elements this exporter does not read",
		"exporter", key.exporter, "version", key.proto.String(), "odid", key.odid,
		"port", port, "template", id, "elements", unread, "suppressed", suppressed)
	return true
}

// nextUnread returns the index of the first field of t from i on that no
// reader consumes, or -1, asking each reader with no value. A v9 scope field
// numbers a scope type rather than an element, so it is passed over.
func (d *Decoder) nextUnread(proto flow.Version, t *template, i int) int {
	var (
		r     flow.Record
		state = fieldState{intern: d.strings}
		opts  optionsState
	)
	for ; i < len(t.fields); i++ {
		f := t.fields[i]
		var read bool
		switch {
		case !t.options:
			read = applyField(&r, &state, f.fieldType, f.enterprise, nil)
		case i >= t.scopeCount:
			read = opts.apply(f.fieldType, f.enterprise, nil)
		case proto == flow.VersionNetFlowV9:
			continue
		default:
			read = opts.applyIPFIXScope(f.fieldType, f.enterprise, nil) || opts.apply(f.fieldType, f.enterprise, nil)
		}
		if !read {
			return i
		}
	}
	return -1
}

// elementName spells a field as its element identifier, behind its
// enterprise number where it has one.
func elementName(f templateField) string {
	id := strconv.FormatUint(uint64(f.fieldType), 10)
	if f.enterprise == 0 {
		return id
	}
	return strconv.FormatUint(uint64(f.enterprise), 10) + "/" + id
}
