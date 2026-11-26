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

// Config configures a Translator. Only NAT64Prefix and IPv4RouterAddress are required. Host bits of prefixes are
// ignored.
type Config struct {
	// RFC 6052 prefix that IPv4 addresses are embedded in: a /32, /40, /48, /56, /64 or /96 IPv6 prefix.
	NAT64Prefix netip.Prefix

	// IPv4 address of the translator. It is the source of the ICMP errors the translator generates (mapped to IPv6
	// for an ICMPv6 error), and of translated ICMPv4 errors whose IPv6 source has no IPv4 mapping (RFC 6791). It must
	// be a unicast address. A non-global address with the Well-Known Prefix needs an EAM entry, which then gives the
	// IPv6 address of the translator.
	IPv4RouterAddress netip.Addr

	// Explicit address mappings (RFC 7757), which take precedence over NAT64Prefix. May be empty. The table is copied,
	// so changing it afterwards does not affect the translator.
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
