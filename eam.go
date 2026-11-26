package siit

import (
	"fmt"
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
	ipv4 netip.Prefix
	ipv6 netip.Prefix
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

		mapping := &eamMapping{ipv4: ipv4Prefix, ipv6: ipv6Prefix}
		ipv4, ipv6 := ipv4Prefix.Addr().As4(), ipv6Prefix.Addr().As16()
		if !insertEAMMapping(lookup.ipv4Root, ipv4[:], ipv4Prefix.Bits(), mapping) {
			return nil, fmt.Errorf("EAM entry at index %d: duplicate IPv4 prefix %v", index, ipv4Prefix)
		}

		if !insertEAMMapping(lookup.ipv6Root, ipv6[:], ipv6Prefix.Bits(), mapping) {
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
	if ipv6Bits+32-ipv4Bits > 128 {
		return ipv4Prefix, ipv6Prefix, fmt.Errorf("%v cannot carry the IPv4 suffix of %v", entry.IPv6Prefix, entry.IPv4Prefix)
	}

	return ipv4Prefix, ipv6Prefix, nil
}

// Inserts a mapping into the EAM lookup tree. Returns false if the prefix already has a mapping.
func insertEAMMapping(root *eamNode, address []byte, bits int, mapping *eamMapping) bool {
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
func lookupEAMMapping(root *eamNode, address []byte, bits int) *eamMapping {
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

// Maps an IPv4 address to an IPv6 address using the EAM lookup table. Returns false if no mapping is found.
func (t *Translator) mapIPv4ToIPv6EAM(ipv4 netip.Addr) (netip.Addr, bool) {
	address := ipv4.As4()
	mapping := lookupEAMMapping(t.eamLookup.ipv4Root, address[:], 32)
	if mapping == nil {
		return netip.Addr{}, false
	}

	result := mapping.ipv6.Addr().As16()
	for offset := 0; offset < 32-mapping.ipv4.Bits(); offset++ {
		setBit(result[:], mapping.ipv6.Bits()+offset, getBit(address[:], mapping.ipv4.Bits()+offset))
	}

	return netip.AddrFrom16(result), true
}

// Maps an IPv6 address to an IPv4 address using the EAM lookup table. Returns false if no mapping is found.
func (t *Translator) mapIPv6ToIPv4EAM(ipv6 netip.Addr) (netip.Addr, bool) {
	address := ipv6.As16()
	mapping := lookupEAMMapping(t.eamLookup.ipv6Root, address[:], 128)
	if mapping == nil {
		return netip.Addr{}, false
	}

	result := mapping.ipv4.Addr().As4()
	for offset := 0; offset < 32-mapping.ipv4.Bits(); offset++ {
		setBit(result[:], mapping.ipv4.Bits()+offset, getBit(address[:], mapping.ipv6.Bits()+offset))
	}

	return netip.AddrFrom4(result), true
}
