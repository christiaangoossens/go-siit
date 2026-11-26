package siit

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// RFC 7757 (EAMT)

// EAMEntry maps an IPv4 prefix to an IPv6 prefix. A single address is a prefix of 32 or 128 bits. Host bits are
// ignored.
type EAMEntry struct {
	IPv4Prefix netip.Prefix
	IPv6Prefix netip.Prefix
}

// EAMTable is a collection of explicit address mappings. The longest matching prefix wins.
type EAMTable []EAMEntry

// ParseEAMEntry parses an entry from its text form, like ParseEAMEntry("192.0.2.0/24", "2001:db8::/120"), and checks
// it like NewTranslator does. An invalid entry returns an error wrapping ErrInvalidConfig.
//
// RFC 7757 Section 3.2 (MUST): "The prefix length MAY be omitted, in which case the implementation MUST assume it to
// be 32 for IPv4 and 128 for IPv6."
func ParseEAMEntry(ipv4Prefix, ipv6Prefix string) (EAMEntry, error) {
	ipv4, err := parseEAMPrefix(ipv4Prefix)
	if err != nil {
		return EAMEntry{}, fmt.Errorf("%w: invalid EAM IPv4 prefix: %w", ErrInvalidConfig, err)
	}

	ipv6, err := parseEAMPrefix(ipv6Prefix)
	if err != nil {
		return EAMEntry{}, fmt.Errorf("%w: invalid EAM IPv6 prefix: %w", ErrInvalidConfig, err)
	}

	entry := EAMEntry{IPv4Prefix: ipv4, IPv6Prefix: ipv6}
	if _, _, err := validateEAMEntry(entry); err != nil {
		return EAMEntry{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return entry, nil
}

func parseEAMPrefix(prefix string) (netip.Prefix, error) {
	if strings.Contains(prefix, "/") {
		return netip.ParsePrefix(prefix)
	}

	address, err := netip.ParseAddr(prefix)
	if err != nil {
		return netip.Prefix{}, err
	}

	return netip.PrefixFrom(address, address.BitLen()), nil
}

type eamMapping struct {
	ipv4     net.IP
	ipv6     net.IP
	ipv4Bits int
	ipv6Bits int
}

type eamNode struct {
	children [2]*eamNode
	mapping  *eamMapping
}

type eamLookup struct {
	ipv4Root *eamNode
	ipv6Root *eamNode
}

// Constructs the EAM lookup tree from the given table. Returns an error if the table is invalid.
func newEAMLookup(table EAMTable) (*eamLookup, error) {
	lookup := &eamLookup{ipv4Root: &eamNode{}, ipv6Root: &eamNode{}}
	for index, entry := range table {
		ipv4Prefix, ipv6Prefix, err := validateEAMEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("EAM entry at index %d: %w", index, err)
		}

		ipv4, ipv6 := net.IP(ipv4Prefix.Addr().AsSlice()), net.IP(ipv6Prefix.Addr().AsSlice())
		mapping := &eamMapping{ipv4: ipv4, ipv6: ipv6, ipv4Bits: ipv4Prefix.Bits(), ipv6Bits: ipv6Prefix.Bits()}
		if !insertEAMMapping(lookup.ipv4Root, mapping.ipv4, mapping.ipv4Bits, mapping) {
			return nil, fmt.Errorf("EAM entry at index %d: duplicate IPv4 prefix %v", index, ipv4Prefix)
		}

		if !insertEAMMapping(lookup.ipv6Root, mapping.ipv6, mapping.ipv6Bits, mapping) {
			return nil, fmt.Errorf("EAM entry at index %d: duplicate IPv6 prefix %v", index, ipv6Prefix)
		}
	}

	return lookup, nil
}

// validateEAMEntry returns the prefixes of the entry with their host bits cleared.
func validateEAMEntry(entry EAMEntry) (netip.Prefix, netip.Prefix, error) {
	ipv4Prefix, ipv6Prefix := entry.IPv4Prefix.Masked(), entry.IPv6Prefix.Masked()
	if !ipv4Prefix.IsValid() || !ipv4Prefix.Addr().Is4() {
		return ipv4Prefix, ipv6Prefix, fmt.Errorf("invalid IPv4 prefix %v", entry.IPv4Prefix)
	}

	if !ipv6Prefix.IsValid() || !ipv6Prefix.Addr().Is6() || ipv6Prefix.Addr().Is4In6() {
		return ipv4Prefix, ipv6Prefix, fmt.Errorf("invalid IPv6 prefix %v", entry.IPv6Prefix)
	}

	ipv4Bits, ipv6Bits := ipv4Prefix.Bits(), ipv6Prefix.Bits()

	// RFC 7757 Section 3.2 requires the IPv4 prefix to have no more
	// suffix bits than its corresponding IPv6 prefix. This leaves room
	// for every IPv4 suffix bit in the RFC 7757 Section 3.3.1 result.
	if ipv6Bits+32-ipv4Bits > net.IPv6len*8 {
		return ipv4Prefix, ipv6Prefix, fmt.Errorf("%v cannot carry the IPv4 suffix of %v", entry.IPv6Prefix, entry.IPv4Prefix)
	}

	return ipv4Prefix, ipv6Prefix, nil
}

// Inserts a mapping into the EAM lookup tree. Returns false if the prefix already has a mapping.
func insertEAMMapping(root *eamNode, address net.IP, bits int, mapping *eamMapping) bool {
	node := root
	for bitIndex := 0; bitIndex < bits; bitIndex++ {
		bit := getBit(address, bitIndex)
		if node.children[bit] == nil {
			node.children[bit] = &eamNode{}
		}
		node = node.children[bit]
	}

	if node.mapping != nil {
		return false
	}

	node.mapping = mapping
	return true
}

// Gets the longest prefix match for the given address in the EAM lookup tree. Returns nil if no match is found.
func lookupEAMMapping(root *eamNode, address net.IP, bits int) *eamMapping {
	if address == nil {
		return nil
	}

	if bits == net.IPv4len*8 {
		address = address.To4()
	} else {
		address = address.To16()
	}

	node := root
	var match *eamMapping
	for bitIndex := 0; bitIndex < bits; bitIndex++ {
		if node.mapping != nil {
			match = node.mapping
		}

		node = node.children[getBit(address, bitIndex)]
		if node == nil {
			return match
		}
	}

	if node.mapping != nil {
		match = node.mapping
	}

	return match
}

// Maps an IPv4 address to an IPv6 address using the EAM lookup table. Returns nil if no mapping is found.
func (t *Translator) mapIPv4ToIPv6EAM(ipv4 net.IP) net.IP {
	ipv4 = ipv4.To4()
	if ipv4 == nil || t.eamLookup == nil {
		return nil
	}

	mapping := lookupEAMMapping(t.eamLookup.ipv4Root, ipv4, net.IPv4len*8)
	if mapping == nil {
		return nil
	}

	result := append(net.IP(nil), mapping.ipv6...)
	for offset := 0; offset < net.IPv4len*8-mapping.ipv4Bits; offset++ {
		setBit(result, mapping.ipv6Bits+offset, getBit(ipv4, mapping.ipv4Bits+offset))
	}

	return result
}

// Maps an IPv6 address to an IPv4 address using the EAM lookup table. Returns nil if no mapping is found.
func (t *Translator) mapIPv6ToIPv4EAM(ipv6 net.IP) net.IP {
	ipv6 = ipv6.To16()
	if ipv6 == nil || t.eamLookup == nil {
		return nil
	}

	mapping := lookupEAMMapping(t.eamLookup.ipv6Root, ipv6, net.IPv6len*8)
	if mapping == nil {
		return nil
	}

	result := append(net.IP(nil), mapping.ipv4...)
	for offset := 0; offset < net.IPv4len*8-mapping.ipv4Bits; offset++ {
		setBit(result, mapping.ipv4Bits+offset, getBit(ipv6, mapping.ipv6Bits+offset))
	}

	return result
}
