package siit

import (
	"fmt"
	"net"
	"strings"
)

// This file implements RFC 7757 (EAMT) and RFC6052 (IPv6 Addressing of IPv4/IPv6 Translators).

// EAMEntry describes one explicit IPv4-to-IPv6 address input mapping.
type RawEAMEntry struct {
	IPv4Prefix string
	IPv6Prefix string
}

// EAMTable is a collection of explicit address mappings.
type RawEAMTable []RawEAMEntry

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
func newEAMLookup(table RawEAMTable) (*eamLookup, error) {
	lookup := &eamLookup{ipv4Root: &eamNode{}, ipv6Root: &eamNode{}}
	for index, entry := range table {
		ipv4, ipv4Net, err := parseEAMPrefix(entry.IPv4Prefix, net.IPv4len*8)
		if err != nil || ipv4.To4() == nil {
			return nil, fmt.Errorf("invalid EAM IPv4 prefix at index %d: %q", index, entry.IPv4Prefix)
		}

		ipv6, ipv6Net, err := parseEAMPrefix(entry.IPv6Prefix, net.IPv6len*8)
		if err != nil || ipv6.To4() != nil {
			return nil, fmt.Errorf("invalid EAM IPv6 prefix at index %d: %q", index, entry.IPv6Prefix)
		}

		ipv4Bits, _ := ipv4Net.Mask.Size()
		ipv6Bits, _ := ipv6Net.Mask.Size()

		// RFC 7757 Section 3.2 requires the IPv4 prefix to have no more
		// suffix bits than its corresponding IPv6 prefix. This leaves room
		// for every IPv4 suffix bit in the RFC 7757 Section 3.3.1 result.
		if ipv6Bits+32-ipv4Bits > net.IPv6len*8 {
			return nil, fmt.Errorf("EAM entry at index %d cannot carry its IPv4 suffix", index)
		}

		mapping := &eamMapping{ipv4: ipv4Net.IP.To4(), ipv6: ipv6Net.IP.To16(), ipv4Bits: ipv4Bits, ipv6Bits: ipv6Bits}
		if err := insertEAMMapping(lookup.ipv4Root, mapping.ipv4, mapping.ipv4Bits, mapping); err != nil {
			return nil, err
		}
		if err := insertEAMMapping(lookup.ipv6Root, mapping.ipv6, mapping.ipv6Bits, mapping); err != nil {
			return nil, err
		}
	}

	return lookup, nil
}

func parseEAMPrefix(prefix string, addressBits int) (net.IP, *net.IPNet, error) {
	if !strings.Contains(prefix, "/") {
		prefix += fmt.Sprintf("/%d", addressBits)
	}

	return net.ParseCIDR(prefix)
}

// Inserts a mapping into the EAM lookup tree. Returns an error if the mapping already exists.
func insertEAMMapping(root *eamNode, address net.IP, bits int, mapping *eamMapping) error {
	node := root
	for bitIndex := 0; bitIndex < bits; bitIndex++ {
		bit := getBit(address, bitIndex)
		if node.children[bit] == nil {
			node.children[bit] = &eamNode{}
		}
		node = node.children[bit]
	}

	if node.mapping != nil {
		return fmt.Errorf("duplicate EAM prefix")
	}

	node.mapping = mapping
	return nil
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

func getBit(address net.IP, bitIndex int) byte {
	return address[bitIndex/8] >> uint(7-bitIndex%8) & 1
}

func setBit(address net.IP, bitIndex int, value byte) {
	mask := byte(1 << uint(7-bitIndex%8))
	if value != 0 {
		address[bitIndex/8] |= mask
	} else {
		address[bitIndex/8] &^= mask
	}
}

func isRFC6052PrefixLength(bits int) bool {
	return bits == 96 || (bits >= 32 && bits <= 64 && bits%8 == 0)
}

func validateRFC6052Prefix(prefix *net.IPNet) error {
	if prefix == nil || prefix.Mask == nil {
		return fmt.Errorf("Invalid NAT64 prefix: %v", prefix)
	}

	maskSize, maskBits := prefix.Mask.Size()
	if maskBits != net.IPv6len*8 || !isRFC6052PrefixLength(maskSize) || prefix.IP.To4() != nil {
		return fmt.Errorf("NAT64 prefix must be an IPv6 /32, /40, /48, /56, /64, or /96 prefix, got: %v", prefix)
	}

	return nil
}

func mapIPv4ToIPv6RFC6052(prefix *net.IPNet, ipv4 net.IP) net.IP {
	prefixBits, _ := prefix.Mask.Size()
	ipv6 := make(net.IP, net.IPv6len)
	copy(ipv6, prefix.IP.To16())
	ipv4 = ipv4.To4()

	if prefixBits == 96 {
		copy(ipv6[12:], ipv4)
		return ipv6
	}

	// RFC 6052 reserves bits 64-71 as the zero-valued "u" octet for
	// every prefix length other than /96.
	firstBits := 64 - prefixBits
	for bitIndex := 0; bitIndex < firstBits; bitIndex++ {
		setBit(ipv6, prefixBits+bitIndex, getBit(ipv4, bitIndex))
	}
	for bitIndex := firstBits; bitIndex < net.IPv4len*8; bitIndex++ {
		setBit(ipv6, 72+bitIndex-firstBits, getBit(ipv4, bitIndex))
	}

	return ipv6
}

func mapIPv6ToIPv4RFC6052(prefix *net.IPNet, ipv6 net.IP) net.IP {
	prefixBits, _ := prefix.Mask.Size()
	ipv6 = ipv6.To16()
	ipv4 := make(net.IP, net.IPv4len)

	if prefixBits == 96 {
		copy(ipv4, ipv6[12:])
		return ipv4
	}

	firstBits := 64 - prefixBits
	for bitIndex := 0; bitIndex < firstBits; bitIndex++ {
		setBit(ipv4, bitIndex, getBit(ipv6, prefixBits+bitIndex))
	}
	for bitIndex := firstBits; bitIndex < net.IPv4len*8; bitIndex++ {
		setBit(ipv4, bitIndex, getBit(ipv6, 72+bitIndex-firstBits))
	}

	return ipv4
}

func (t *Translator) mapIPv4ToIPv6(ipv4 net.IP) net.IP {
	// Check if already present in table
	if mapped := t.mapIPv4ToIPv6EAM(ipv4); mapped != nil {
		return mapped
	}

	return mapIPv4ToIPv6RFC6052(t.nat64Net, ipv4)
}

func (t *Translator) mapIPv6ToIPv4(ipv6 net.IP) net.IP {
	// Check if already present in table
	if mapped := t.mapIPv6ToIPv4EAM(ipv6); mapped != nil {
		return mapped
	}

	// Check if the IPv6 address is within the NAT64 prefix
	if t.nat64Net.Contains(ipv6) {
		return mapIPv6ToIPv4RFC6052(t.nat64Net, ipv6)
	}

	// Else, special case: use our ipv4 router address as we cannot translate
	return t.ipv4RouterAddress
}

func (t *Translator) hasIPv6ToIPv4Mapping(ipv6 net.IP) bool {
	if t.nat64Net.Contains(ipv6) {
		return true
	}

	return ipv6.To16() != nil && t.eamLookup != nil && lookupEAMMapping(t.eamLookup.ipv6Root, ipv6, net.IPv6len*8) != nil
}
