// This file anchors the uptime-relative flow clocks. Every NetFlow version
// times a flow in milliseconds of device uptime, a 32-bit counter that wraps,
// so an instant is an age measured back from the export rather than an offset
// forward from a boot instant.

package decoder

import "time"

const (
	// uptimeWrapMs is the period of the 32-bit millisecond uptime counters,
	// 49.7 days.
	uptimeWrapMs = int64(1) << 32

	// clockSkewToleranceMs is how far past the export uptime an instant may
	// sit before the difference reads as a wrap rather than as the device's
	// own skew. IE 160 sets the floor at a second: an IPFIX header times its
	// export in whole seconds, so an uptime derived from it trails the
	// instants it anchors by up to 999 ms. Nothing on the wire bounds a
	// flow's age -- a permanent cache ages none out -- so the ceiling is a
	// policy one. Either reading shifts a pair by the same amount, which
	// leaves the duration between them intact.
	clockSkewToleranceMs = int64(time.Hour / time.Millisecond)
)

// exportClock is a header's own view of time: when the datagram left the
// device, and what the device's uptime counter read at that instant. IPFIX
// states no uptime, so its records carry the boot instant in IE 160 instead.
type exportClock struct {
	at        time.Time
	uptimeMs  uint32
	hasUptime bool
}

// withBootTime derives the export uptime for the protocol whose header states
// none. Adding an element to the boot instant directly would drift by a whole
// period once the flow's own uptime passes the counter's range, the element
// being 32-bit while the boot instant is absolute.
func (c exportClock) withBootTime(at time.Time) exportClock {
	if c.hasUptime || at.IsZero() {
		return c
	}
	c.uptimeMs = uint32(c.at.Sub(at).Milliseconds()) //nolint:gosec // Modular by construction.
	c.hasUptime = true
	return c
}

// anchor turns one uptime-relative instant into an absolute one. The age is
// the modular difference, so an instant recorded before a wrap reads as its
// own age rather than as a 49-day future. Only a difference within the
// tolerance of a whole period is read the other way, as an instant the export
// uptime has not reached yet.
func (c exportClock) anchor(valueMs uint32) time.Time {
	age := int64(c.uptimeMs - valueMs)
	if age > uptimeWrapMs-clockSkewToleranceMs {
		age -= uptimeWrapMs
	}
	return c.at.Add(-time.Duration(age) * time.Millisecond)
}

// anchorPair is the whole-record form, which NetFlow v5 and v8 reach
// directly, having no field state to resolve first.
func (c exportClock) anchorPair(firstMs, lastMs uint32) (start, end time.Time, ok bool) {
	return withholdInverted(c.anchor(firstMs), c.anchor(lastMs))
}

// withholdInverted drops a pair that ends before it begins, whichever
// elements carried it. A flow ending before it began is not a reading, and
// its negative duration would reach the histogram as a span no device
// measured. Both instants go, one of them being no use without the other.
func withholdInverted(start, end time.Time) (from, to time.Time, ok bool) {
	if end.Before(start) {
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}
