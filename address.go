package siit

import (
	"fmt"
	"net"
)

/**
 * RFC 6052 (IPv6 Addressing of IPv4/IPv6 Translators)
 */

func isRFC6052PrefixLength(bits int) bool {
	return bits == 96 || (bits >= 32 && bits <= 64 && bits%8 == 0)
}

// RFC 6052 Section 3.1 forbids representing these non-global IPv4 addresses specifically for the Well-Known Prefix.
var nonGlobalIPv4Networks = func() []*net.IPNet {
	var networks []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/3",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		networks = append(networks, network)
	}
	return networks
}()

func isNonGlobalIPv4(ipv4 net.IP) bool {
	for _, network := range nonGlobalIPv4Networks {
		if network.Contains(ipv4) {
			return true
		}
	}

	return false
}

var wellKnownPrefix = net.ParseIP("64:ff9b::")

func isWellKnownPrefix(prefix *net.IPNet) bool {
	ones, _ := prefix.Mask.Size()
	return ones == 96 && prefix.IP.Equal(wellKnownPrefix)
}

func validateRFC6052Prefix(prefix *net.IPNet) error {
	if prefix == nil || prefix.Mask == nil {
		return fmt.Errorf("Invalid NAT64 prefix: %v", prefix)
	}

	maskSize, maskBits := prefix.Mask.Size()
	if maskBits != net.IPv6len*8 || !isRFC6052PrefixLength(maskSize) || prefix.IP.To4() != nil {
		return fmt.Errorf("NAT64 prefix must be an IPv6 /32, /40, /48, /56, /64, or /96 prefix, got: %v", prefix)
	}

	// RFC 6052 Section 2.2: bits 64-71 (the "u" octet) MUST be zero. Shorter prefixes never reach them, but a /96
	// prefix contains them, so the administrator has to configure them as zero.
	if prefix.IP.To16()[8] != 0 {
		return fmt.Errorf("NAT64 prefix must have a zero u octet (bits 64-71), got: %v", prefix)
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

// isForbiddenIPv4 reports whether RFC 6052 Section 3.1 forbids translating this IPv4 address. EAM entries are explicit and therefore exempt.
func (t *Translator) isForbiddenIPv4(ipv4 net.IP) bool {
	if t.mapIPv4ToIPv6EAM(ipv4) != nil {
		return false
	}

	return isWellKnownPrefix(t.nat64Net) && isNonGlobalIPv4(ipv4)
}

func (t *Translator) isForbiddenIPv6(ipv6 net.IP) bool {
	if !isWellKnownPrefix(t.nat64Net) || t.mapIPv6ToIPv4EAM(ipv6) != nil || !t.nat64Net.Contains(ipv6) {
		return false
	}

	return isNonGlobalIPv4(mapIPv6ToIPv4RFC6052(t.nat64Net, ipv6))
}

/**
 * General mapping functions
 */

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
