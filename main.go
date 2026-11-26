package siit

import (
	"fmt"
	"net"
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

	// MTU is the IPv6 path MTU used to determine the maximum IPv4 packet size.
	MTU uint32
}

// NewTranslator creates a SIIT translator with the default IPv6 minimum MTU.
func NewTranslator(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable) (*Translator, error) {
	return NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, eamTable, ipv6MinimumMTU)
}

// NewTranslatorWithMTU creates a SIIT translator with the supplied IPv6 path MTU.
func NewTranslatorWithMTU(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable, mtu uint32) (*Translator, error) {
	if mtu < ipv6MinimumMTU {
		return nil, ErrInvalidMTU
	}

	if err := validateRFC6052Prefix(nat64Net); err != nil {
		return nil, err
	}

	// Check that the IPv4 router address is a valid IPv4 address
	if ipv4RouterAddress == nil || ipv4RouterAddress.To4() == nil {
		return nil, fmt.Errorf("Invalid IPv4 router address: %v", ipv4RouterAddress)
	}

	eamLookup, err := newEAMLookup(eamTable)
	if err != nil {
		return nil, err
	}

	return &Translator{
		nat64Net:          nat64Net,
		wellKnownPrefix:   isWellKnownPrefix(nat64Net),
		ipv4RouterAddress: ipv4RouterAddress,
		eamLookup:         eamLookup,
		identifications:   newIdentificationGenerator(),
		MTU:               mtu,
	}, nil
}

func (t *Translator) maxIPv4PacketLength(fragmented bool) uint32 {
	if fragmented {
		return t.MTU - ipv6HeaderLength - ipv6FragmentHeaderLength + ipv4HeaderLength
	}

	return t.MTU - ipv6HeaderLength + ipv4HeaderLength
}
