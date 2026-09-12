// This file puts each side of a flow on the VLAN the operator's own file
// gives its address.

package enrich

import (
	"net/netip"
	"slices"

	"github.com/umatare5/xflow-exporter/internal/flow"
)

// VLAN puts each address on the VLAN one device's entry in the mapping file
// assigns its prefix.
//
// What it fills is where an address lives, which no flow protocol exports.
// The VLAN a device can report is the one its own observation point sat in,
// so the two are different readings and neither stands in for the other.
//
// The file is owned by Mapping, so this source re-reads nothing: it consults
// the snapshot in force through the same atomic pointer a scrape reads, and a
// reload of that file takes effect here with it.
type VLAN struct {
	counters
	mapping *Mapping
}

// NewVLAN builds the enricher over an already loaded mapping.
func NewVLAN(mapping *Mapping) *VLAN {
	return &VLAN{mapping: mapping}
}

// Name implements Enricher.
func (v *VLAN) Name() string {
	return "vlan"
}

// Snapshot implements Enricher.
func (v *VLAN) Snapshot() Snapshot {
	return v.snapshot(v.Name())
}

// Enrich puts each side on its VLAN, and leaves a side no prefix covers at
// zero.
//
// Nothing is ever skipped for a device reading, as no protocol exports the
// dimension this fills. A record neither side of which is covered counts as
// unknown, which is the ordinary reading for a file that names the local
// segments and nothing beyond them.
func (v *VLAN) Enrich(r *flow.Record) {
	set := v.mapping.Names()
	if set == nil {
		v.unknown.Add(1)
		return
	}

	table, held := set.vlans[r.Exporter]
	if !held {
		v.unknown.Add(1)
		return
	}

	filled := false
	if r.SrcAddr.IsValid() {
		if id, ok := table.lookup(r.SrcAddr); ok {
			r.SrcVLAN = id
			filled = true
		}
	}
	if r.DstAddr.IsValid() {
		if id, ok := table.lookup(r.DstAddr); ok {
			r.DstVLAN = id
			filled = true
		}
	}

	if filled {
		v.filled.Add(1)
		return
	}
	v.unknown.Add(1)
}

// vlanTable resolves one device's addresses to VLANs.
//
// The prefixes are held by their masked form so a lookup is a map probe
// rather than a walk: an address is rounded to each length the device's entry
// declares and the result looked up whole. The lengths are distinct and
// descending, so the first hit is the longest match and a nested prefix wins
// over the one containing it.
//
// Expanding the prefixes to hosts would answer in one probe, but a single
// IPv4 /8 is 16.7 million keys and no IPv6 prefix can be expanded at all.
// Walking the prefixes instead would cost one Contains per entry, where this
// costs one probe per distinct length: the entries are what an operator adds
// to, and the lengths are not.
type vlanTable struct {
	// lengths4 and lengths6 are kept apart so every rounding is in range for
	// the address it rounds. A length past the address width yields an
	// invalid prefix, which would merely miss this map, so the split is what
	// keeps each probe meaningful rather than what makes the answer right. It
	// is also the shorter walk of the two.
	lengths4 []int
	lengths6 []int
	prefixes map[netip.Prefix]uint16
}

// lookup resolves one address, reporting false where no prefix covers it.
func (t *vlanTable) lookup(addr netip.Addr) (uint16, bool) {
	lengths := t.lengths6
	if addr.Is4() {
		lengths = t.lengths4
	}

	for _, bits := range lengths {
		//nolint:errcheck // The length came from a prefix of this family, so it is in range.
		rounded, _ := addr.Prefix(bits)
		if id, ok := t.prefixes[rounded]; ok {
			return id, true
		}
	}
	return 0, false
}

// add records one prefix under one VLAN, reporting false where the device
// already assigned that prefix. Two VLANs claiming one prefix is a file whose
// answer depends on map order, which is a contradiction rather than a
// precedence to resolve.
func (t *vlanTable) add(prefix netip.Prefix, id uint16) bool {
	if _, taken := t.prefixes[prefix]; taken {
		return false
	}
	t.prefixes[prefix] = id

	lengths := &t.lengths6
	if prefix.Addr().Is4() {
		lengths = &t.lengths4
	}
	if !slices.Contains(*lengths, prefix.Bits()) {
		*lengths = append(*lengths, prefix.Bits())
		// Descending, so lookup's first hit is the longest match.
		slices.Sort(*lengths)
		slices.Reverse(*lengths)
	}
	return true
}
