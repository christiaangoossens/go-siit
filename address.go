package siit

import (
	"fmt"
	"net/netip"
)

// RFC 6052 (IPv6 Addressing of IPv4/IPv6 Translators)

func isRFC6052PrefixLength(bits int) bool {
	return bits == 96 || (bits >= 32 && bits <= 64 && bits%8 == 0)
}

// RFC 6052 Section 3.1 forbids representing these non-global IPv4 addresses specifically for the Well-Known Prefix.
var nonGlobalIPv4Networks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

func isNonGlobalIPv4(ipv4 netip.Addr) bool {
	for _, network := range nonGlobalIPv4Networks {
		if network.Contains(ipv4) {
			return true
		}
	}

	return false
}

var wellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")

// validateRFC6052Prefix returns the prefix with its host bits cleared.
func validateRFC6052Prefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || !isRFC6052PrefixLength(prefix.Bits()) {
		return netip.Prefix{}, fmt.Errorf("NAT64 prefix must be an IPv6 /32, /40, /48, /56, /64, or /96 prefix, got: %v", prefix)
	}

	prefix = prefix.Masked()

	// RFC 6052 Section 2.2: bits 64-71 (the "u" octet) MUST be zero. Shorter prefixes never reach them, but a /96
	// prefix contains them, so the administrator has to configure them as zero.
	if prefix.Addr().As16()[8] != 0 {
		return netip.Prefix{}, fmt.Errorf("NAT64 prefix must have a zero u octet (bits 64-71), got: %v", prefix)
	}

	return prefix, nil
}

func mapIPv4ToIPv6RFC6052(prefix netip.Prefix, ipv4 netip.Addr) netip.Addr {
	prefixBits := prefix.Bits()
	ipv6 := prefix.Addr().As16()
	embedded := ipv4.As4()

	if prefixBits == 96 {
		copy(ipv6[12:], embedded[:])
		return netip.AddrFrom16(ipv6)
	}

	// RFC 6052 reserves bits 64-71 as the zero-valued "u" octet for
	// every prefix length other than /96.
	firstBits := 64 - prefixBits
	for bitIndex := 0; bitIndex < firstBits; bitIndex++ {
		setBit(ipv6[:], prefixBits+bitIndex, getBit(embedded[:], bitIndex))
	}
	for bitIndex := firstBits; bitIndex < 32; bitIndex++ {
		setBit(ipv6[:], 72+bitIndex-firstBits, getBit(embedded[:], bitIndex))
	}

	return netip.AddrFrom16(ipv6)
}

func mapIPv6ToIPv4RFC6052(prefix netip.Prefix, ipv6 netip.Addr) netip.Addr {
	prefixBits := prefix.Bits()
	address := ipv6.As16()
	var ipv4 [4]byte

	if prefixBits == 96 {
		copy(ipv4[:], address[12:])
		return netip.AddrFrom4(ipv4)
	}

	firstBits := 64 - prefixBits
	for bitIndex := 0; bitIndex < firstBits; bitIndex++ {
		setBit(ipv4[:], bitIndex, getBit(address[:], prefixBits+bitIndex))
	}
	for bitIndex := firstBits; bitIndex < 32; bitIndex++ {
		setBit(ipv4[:], bitIndex, getBit(address[:], 72+bitIndex-firstBits))
	}

	return netip.AddrFrom4(ipv4)
}

// General mapping functions
//
// Each address is looked up once, and the checks read the result. Looking up the EAM table is the most expensive
// step, so it is not repeated per check.

// ipv4Mapping is the IPv6 address that an IPv4 address maps to.
type ipv4Mapping struct {
	ipv6 netip.Addr

	// Whether an EAM entry gave the mapping, rather than the NAT64 prefix.
	eam bool
}

func (t *Translator) resolveIPv4(ipv4 netip.Addr) ipv4Mapping {
	// Check if already present in table
	if mapped, ok := t.mapIPv4ToIPv6EAM(ipv4); ok {
		return ipv4Mapping{ipv6: mapped, eam: true}
	}

	return ipv4Mapping{ipv6: mapIPv4ToIPv6RFC6052(t.nat64Prefix, ipv4)}
}

// isForbiddenIPv4 reports whether RFC 6052 Section 3.1 forbids translating this IPv4 address. EAM entries are explicit and therefore exempt.
func (t *Translator) isForbiddenIPv4(ipv4 netip.Addr, mapping ipv4Mapping) bool {
	return t.wellKnownPrefix && !mapping.eam && isNonGlobalIPv4(ipv4)
}

// ipv6Mapping is the IPv4 address that an IPv6 address maps to. The address is invalid when there is no mapping.
type ipv6Mapping struct {
	ipv4 netip.Addr

	// Whether an EAM entry gave the mapping, rather than the NAT64 prefix.
	eam bool
}

func (t *Translator) resolveIPv6(ipv6 netip.Addr) ipv6Mapping {
	// Check if already present in table
	if mapped, ok := t.mapIPv6ToIPv4EAM(ipv6); ok {
		return ipv6Mapping{ipv4: mapped, eam: true}
	}

	// Check if the IPv6 address is within the NAT64 prefix. An IPv4-mapped address (::ffff:0:0/96) never is, even for
	// a prefix like ::/32 whose bits it shares.
	if !ipv6.Is4In6() && t.nat64Prefix.Contains(ipv6) {
		return ipv6Mapping{ipv4: mapIPv6ToIPv4RFC6052(t.nat64Prefix, ipv6)}
	}

	return ipv6Mapping{}
}

func (m ipv6Mapping) mappable() bool {
	return m.ipv4.IsValid()
}

func (t *Translator) isForbiddenIPv6(mapping ipv6Mapping) bool {
	return t.wellKnownPrefix && mapping.mappable() && !mapping.eam && isNonGlobalIPv4(mapping.ipv4)
}

// isIllegalIPv4Embedded reports whether an IPv6 address inside the NAT64 prefix embeds an IPv4 address that is not
// global unicast (unspecified, loopback, link-local, multicast, broadcast). Such an address would be an illegal IPv4
// source or destination (RFC 1812 Section 5.3.7). EAM entries are explicit and therefore exempt.
func isIllegalIPv4Embedded(mapping ipv6Mapping) bool {
	return mapping.mappable() && !mapping.eam && !mapping.ipv4.IsGlobalUnicast()
}
