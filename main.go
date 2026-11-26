package siit

import (
	"fmt"
	"net"
	"net/netip"
)

// Translator converts packets between IPv4 and IPv6 according to SIIT.
type Translator struct {
	// Network prefix used for NAT64 translation, as defined in RFC 6052.
	nat64Net *net.IPNet

	// Whether nat64Net is the Well-Known Prefix (RFC 6052 Section 2.1).
	wellKnownPrefix bool

	// IPv4 address used for routing and ICMP error generation
	ipv4RouterAddress net.IP

	// EAM table (RFC 7757)
	eamLookup *eamLookup

	// Fragment Identification generator for IPv4 packets without a Fragment Header (RFC 7915 Section 5.1).
	identifications *identificationGenerator

	// IPv6 path MTU used to determine the maximum IPv4 packet size.
	mtu uint32
}

// Config configures a Translator. Only NAT64Prefix and IPv4RouterAddress are required.
type Config struct {
	// RFC 6052 prefix that IPv4 addresses are embedded in: a /32, /40, /48, /56, /64 or /96 IPv6 prefix.
	NAT64Prefix netip.Prefix

	// IPv4 source address of ICMPv4 errors whose IPv6 source has no IPv4 mapping (RFC 6791).
	IPv4RouterAddress netip.Addr

	// Explicit address mappings (RFC 7757), which take precedence over NAT64Prefix. May be empty.
	EAMTable EAMTable

	// IPv6 path MTU, at least 1280. Zero means 1280.
	MTU uint32
}

// NewTranslator creates a translator. It is immutable and safe for concurrent use. An invalid configuration returns
// an error wrapping ErrInvalidConfig or ErrInvalidMTU.
func NewTranslator(config Config) (*Translator, error) {
	mtu := config.MTU
	if mtu == 0 {
		mtu = ipv6MinimumMTU
	}

	if mtu < ipv6MinimumMTU {
		return nil, ErrInvalidMTU
	}

	nat64Net, err := validateRFC6052Prefix(config.NAT64Prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	router := config.IPv4RouterAddress.Unmap()
	if !router.Is4() {
		return nil, fmt.Errorf("%w: invalid IPv4 router address: %v", ErrInvalidConfig, config.IPv4RouterAddress)
	}

	eamLookup, err := newEAMLookup(config.EAMTable)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return &Translator{
		nat64Net:          nat64Net,
		wellKnownPrefix:   isWellKnownPrefix(nat64Net),
		ipv4RouterAddress: net.IP(router.AsSlice()),
		eamLookup:         eamLookup,
		identifications:   newIdentificationGenerator(),
		mtu:               mtu,
	}, nil
}

func (t *Translator) maxIPv4PacketLength(fragmented bool) uint32 {
	if fragmented {
		return t.mtu - ipv6HeaderLength - ipv6FragmentHeaderLength + ipv4HeaderLength
	}

	return t.mtu - ipv6HeaderLength + ipv4HeaderLength
}
