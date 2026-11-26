package siit

import (
	"fmt"
	"net/netip"
)

// Translator converts packets between IPv4 and IPv6 according to SIIT.
type Translator struct {
	// Network prefix used for NAT64 translation, as defined in RFC 6052.
	nat64Prefix netip.Prefix

	// Whether nat64Prefix is the Well-Known Prefix (RFC 6052 Section 2.1).
	wellKnownPrefix bool

	// IPv4 address used for routing and ICMP error generation
	ipv4RouterAddress netip.Addr

	// ipv4RouterAddress mapped to IPv6, the source of generated ICMPv6 errors.
	ipv6RouterAddress netip.Addr

	// EAM table (RFC 7757)
	eamLookup *eamLookup

	// Fragment Identification generator for IPv4 packets without a Fragment Header (RFC 7915 Section 5.1).
	identifications *identificationGenerator

	// IPv6 path MTU used to determine the maximum IPv4 packet size.
	mtu uint32
}

// Config configures a Translator. Only NAT64Prefix and IPv4RouterAddress are required. Bits after a prefix length (host
// bits) are ignored, so 192.0.2.5/24 is read as 192.0.2.0/24.
type Config struct {
	// The IPv6 prefix that IPv4 addresses are put into (embedded in, RFC 6052): a /32, /40, /48, /56, /64 or /96
	// prefix. With 64:ff9b::/96, the IPv4 address 1.2.3.4 becomes 64:ff9b::102:304. Most NAT64 networks use
	// 64:ff9b::/96 (the Well-Known Prefix).
	NAT64Prefix netip.Prefix

	// An IPv4 address that stands for the translator itself. It is the sender of the error messages the translator
	// creates. It also replaces the source of an error message from an IPv6 router that has no IPv4 address
	// (RFC 6791).
	//
	// With 64:ff9b::/96 and a private (non-global) address such as 192.0.0.254, add an EAM entry that maps this address to a
	// public IPv6 address of this machine.
	IPv4RouterAddress netip.Addr

	// Fixed address mappings (Explicit Address Mappings, RFC 7757), such as 'IPv4 192.0.2.1 is IPv6 2001:db8::1'. They take precedence over
	// NAT64Prefix. May be empty. The table is copied, so changing it afterwards does not affect the translator.
	EAMTable EAMTable

	// IPv6 path MTU, at least 1280. Zero means 1280.
	MTU uint32
}

// NewTranslator creates a translator. It is immutable and safe for concurrent use. An invalid configuration returns
// an error wrapping ErrInvalidConfig, and also ErrInvalidMTU for an MTU below 1280.
func NewTranslator(config Config) (*Translator, error) {
	mtu := config.MTU
	if mtu == 0 {
		mtu = ipv6MinimumMTU
	}

	if mtu < ipv6MinimumMTU {
		return nil, fmt.Errorf("%w: %w: %d", ErrInvalidConfig, ErrInvalidMTU, mtu)
	}

	nat64Prefix, err := validateRFC6052Prefix(config.NAT64Prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	router := config.IPv4RouterAddress
	if !router.Is4() || !router.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv4 router address must be a unicast IPv4 address, got: %v", ErrInvalidConfig, router)
	}

	eamLookup, err := newEAMLookup(config.EAMTable)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	translator := &Translator{
		nat64Prefix:       nat64Prefix,
		wellKnownPrefix:   nat64Prefix == wellKnownPrefix,
		ipv4RouterAddress: router,
		eamLookup:         eamLookup,
		identifications:   newIdentificationGenerator(),
		mtu:               mtu,
	}

	// Generated ICMPv6 errors come from the router address mapped to IPv6, so it must be mappable.
	routerMapping := translator.resolveIPv4(router)
	if translator.isForbiddenIPv4(router, routerMapping) {
		return nil, fmt.Errorf("%w: IPv4 router address %v is non-global and cannot use the Well-Known Prefix, add an EAM entry for it", ErrInvalidConfig, router)
	}

	translator.ipv6RouterAddress = routerMapping.ipv6
	return translator, nil
}

func (t *Translator) maxIPv4PacketLength(fragmented bool) uint32 {
	if fragmented {
		return t.mtu - ipv6HeaderLength - ipv6FragmentHeaderLength + ipv4HeaderLength
	}

	return t.mtu - ipv6HeaderLength + ipv4HeaderLength
}
