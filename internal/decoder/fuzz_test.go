package decoder

import (
	"net/netip"
	"testing"
)

// FuzzDecode asserts that no datagram, however broken, panics the decoder or
// yields records alongside an error. Every datagram is untrusted input.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x05})
	f.Add(buildV5Packet(1))
	f.Add(buildV5Packet(netflowV5MaxCount))
	f.Add([]byte{0x00, 0x00, 0x00, 0x05})
	f.Add([]byte{0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00})

	exporter := netip.MustParseAddr("192.0.2.99")

	f.Fuzz(func(t *testing.T, payload []byte) {
		d := New()

		records, err := d.Decode(exporter, payload, nil)
		if err != nil && len(records) != 0 {
			t.Errorf("Decode() returned %d records alongside error %v, want 0", len(records), err)
		}
	})
}
