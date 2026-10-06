package siit

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand/v2"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/**
 * RFC 7915 Section 5 (Translating from IPv6 to IPv4)
 */

// Fragment Identification generator for IPv6-to-IPv4 packets that carry no Fragment Header (RFC 7915 Section 5.1).
// It starts at a random value so the sequence is not trivially predictable (RFC 7739 Section 5).
var nextIdentification = func() *atomic.Uint32 {
	var counter atomic.Uint32
	counter.Store(rand.Uint32())
	return &counter
}()

// TranslateIPv6 translates an IPv6 packet to IPv4.
func (t *Translator) TranslateIPv6(packet gopacket.Packet, overrides TranslationOverrides) (TranslatedPacket, error) {
	translated := TranslatedPacket{}
	quoted := overrides.QuotedPacket

	ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		// Not IPv6 packet, ignore because we are only translating IPv6 here
		return translated, fmt.Errorf("%w: packet has no IPv6 layer", ErrInvalidPacket)
	}

	// Verify that src and dst are both unicast
	if !ip.SrcIP.IsGlobalUnicast() {
		return translated, fmt.Errorf("%w: IPv6 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return translated, fmt.Errorf("%w: IPv6 destination %s is not unicast", ErrUnsupportedDestIP, ip.DstIP)
	}

	// ===
	// Header & checksum validation
	// ===

	// RFC 8200 Section 3 defines a fixed 40-byte IPv6 base header.
	if ip.Version != 6 || len(ip.Contents) < ipv6HeaderLength {
		return translated, fmt.Errorf("%w: invalid IPv6 header", ErrInvalidPacket)
	}

	protocol, payload, offset := ip.NextHeader, ip.Payload, ipv6HeaderLength
	if ip.HopByHop != nil {
		// gopacket already decoded a leading Hop-by-Hop header as part of the IPv6 layer.
		protocol, offset = ip.HopByHop.NextHeader, offset+ip.HopByHop.ActualLength
	}

	// Get the actual contents, skip over any IPv6 extensions (as per RFC 7915, section 1.2)
	// The IPv6
	//  headers HOPOPT (0), IPv6-Route (43), and IPv6-Opts (60) are
	//  skipped over during processing as they have no meaning in IPv4.
	segmentsLeftOffset := 0
	for protocol == layers.IPProtocolIPv6HopByHop || protocol == layers.IPProtocolIPv6Routing || protocol == layers.IPProtocolIPv6Destination {
		// RFC 8200 Section 4.3: Next Header, then Hdr Ext Len in 8-octet units not including the first 8 octets.
		if len(payload) < 8 || len(payload) < (int(payload[1])+1)*8 {
			return translated, fmt.Errorf("%w: truncated IPv6 extension header", ErrInvalidPacket)
		}

		// The Segments Left of a Routing header is its fourth octet.
		if protocol == layers.IPProtocolIPv6Routing && payload[3] != 0 && segmentsLeftOffset == 0 {
			segmentsLeftOffset = offset + 3
		}

		extensionLength := (int(payload[1]) + 1) * 8
		protocol, payload, offset = layers.IPProtocol(payload[0]), payload[extensionLength:], offset+extensionLength
	}

	// A quoted packet is not routed, so its Routing header does not matter.
	if segmentsLeftOffset != 0 && !quoted {
		// The Parameter Problem below is itself an ICMPv6 error, and RFC 4443 Section 2.4 (e.1)
		// forbids sending one in response to an ICMPv6 error message (types 0-127),
		// so such a packet is dropped without a reply.
		if protocol == layers.IPProtocolICMPv6 && len(payload) > 0 && payload[0] < 128 {
			return translated, fmt.Errorf("%w: IPv6 routing header has segments left", ErrInvalidPacket)
		}
		// RFC 7915 Section 5.1: Parameter Problem pointing at Segments Left.
		result := t.generateIPv6ParameterProblem(ip, uint32(segmentsLeftOffset))
		return result, &TranslationError{Err: fmt.Errorf("%w: IPv6 routing header has segments left", ErrInvalidPacket), Packet: result.Packet}
	}

	// ICMPv6 errors may use the IPv4 router address when the outer IPv6 source
	// cannot be mapped to an IPv4 address (RFC 7915 Section 5.2 with RFC 6791 Section 3), since they can
	// come from native IPv6 routers. Ordinary packets would be answered to an address we can't map back.
	// RFC 4443 defines types 0-127 as errors. A quoted packet has no such exception: an ICMP error quoting an ICMP error is not translated.
	routerSource := !quoted && protocol == layers.IPProtocolICMPv6 && len(payload) > 0 && payload[0] < 128

	// RFC 6052 Section 3.1: non-global addresses must not be embedded in the Well-Known Prefix.
	if t.isForbiddenIPv6(ip.SrcIP) {
		return translated, fmt.Errorf("%w: IPv6 source %s embeds a non-global IPv4 address", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !routerSource && !t.hasIPv6ToIPv4Mapping(ip.SrcIP) {
		return translated, fmt.Errorf("%w: IPv6 source %s is not mappable", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if t.isForbiddenIPv6(ip.DstIP) {
		return translated, fmt.Errorf("%w: IPv6 destination %s embeds a non-global IPv4 address", ErrUnsupportedDestIP, ip.DstIP)
	}

	// Only the source may fall back to the router address, so the destination must always be mappable.
	if !t.hasIPv6ToIPv4Mapping(ip.DstIP) {
		return translated, fmt.Errorf("%w: IPv6 destination %s is not mappable", ErrInvalidPacket, ip.DstIP)
	}

	if t.isIllegalIPv4Embedded(ip.SrcIP) {
		return translated, fmt.Errorf("%w: IPv6 source %s embeds an illegal IPv4 address", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if t.isIllegalIPv4Embedded(ip.DstIP) {
		return translated, fmt.Errorf("%w: IPv6 destination %s embeds an illegal IPv4 address", ErrUnsupportedDestIP, ip.DstIP)
	}

	translated.SrcIP = t.mapIPv6ToIPv4(ip.SrcIP)
	translated.DstIP = t.mapIPv6ToIPv4(ip.DstIP)

	// A quoted packet is not sent, so it only needs to be translated.
	if !quoted {
		// Check if the Hop Limit would be 0, if so generate an ICMP Time Exceeded message back to the source of the original packet
		if ip.HopLimit <= 1 {
			packet := t.generateIPv4TimeExceeded(ip)
			return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet.Packet}
		}

		// RFC 8200 Section 8.1: IPv6 UDP checksum zero is invalid and the packet is silently dropped.
		if isZeroUDPChecksum(payload, protocol) {
			return translated, nil
		}

		// Validate transport checksums
		pseudoHeader := ipv6PseudoHeader(ip.SrcIP, ip.DstIP, protocol, len(payload))
		if !validTransportChecksum(pseudoHeader, protocol, payload) {
			return translated, fmt.Errorf("%w: invalid IPv6 transport checksum", ErrInvalidPacket)
		}
	}

	// ===
	// Construction
	// ===

	ttl := ip.HopLimit - 1
	if quoted {
		// For quoted packets, we do not decrement the TTL/Hop Limit, as it is already decremented in the outer packet.
		ttl = ip.HopLimit
	}

	// Create a new IPv4 packet that matches the IPv6 Packet without any payload
	ipv4 := &layers.IPv4{
		Version:    4,
		IHL:        5, // 5 (no IPv4 options)
		TOS:        ip.TrafficClass,
		Length:     0, // Automatically calculated during serialization
		Id:         0, // Set from the IPv6 Fragment Header when present, otherwise from the generator
		Flags:      0, // Set for fragment metadata or when the translated packet exceeds 1260 bytes
		FragOffset: 0, // Set from the IPv6 Fragment Header when present
		TTL:        ttl,
		Protocol:   protocol,
		SrcIP:      translated.SrcIP,
		DstIP:      translated.DstIP,
	}

	fragmented := protocol == layers.IPProtocolIPv6Fragment
	if fragmented {
		// RFC 8200 Section 4.5 requires an M=1 fragment's payload to be an
		// integer multiple of 8 octets. Reserved fields are ignored on reception.
		moreFragments := len(payload) >= ipv6FragmentHeaderLength && payload[3]&1 != 0
		if len(payload) < ipv6FragmentHeaderLength || (!quoted && moreFragments && (len(payload)-ipv6FragmentHeaderLength)%8 != 0) {
			return translated, fmt.Errorf("%w: invalid IPv6 fragment", ErrInvalidPacket)
		}

		protocol = layers.IPProtocol(payload[0])
		if protocol == layers.IPProtocolICMPv6 {
			return translated, fmt.Errorf("%w: fragmented ICMPv6 packets are unsupported", ErrUnsupportedProtocol)
		}

		ipv4.FragOffset = binary.BigEndian.Uint16(payload[2:4]) >> 3
		ipv4.Id = uint16(binary.BigEndian.Uint32(payload[4:8]))
		ipv4.Protocol = protocol

		if moreFragments {
			ipv4.Flags = layers.IPv4MoreFragments
		}

		payload, offset = payload[ipv6FragmentHeaderLength:], offset+ipv6FragmentHeaderLength

		// RFC 7915 Section 5.1.1 says a Fragment Header followed by an
		// extension header should be dropped because IPv4 cannot represent it.
		if isIPv6FragmentExtension(protocol) {
			log.Printf("Dropping IPv6 fragment with extension header %d, which cannot be represented in IPv4", protocol)
			return translated, nil
		}
	}

	// ICMPv6 (58) is changed to ICMPv4 (1).
	if protocol == layers.IPProtocolICMPv6 {
		ipv4.Protocol = layers.IPProtocolICMPv4
	}

	// ===
	// Transport payload
	// ===

	length := int(ip.Length) - (offset - ipv6HeaderLength)
	removed := ipv6PseudoHeader(ip.SrcIP, ip.DstIP, protocol, length)
	added := ipv4PseudoHeader(ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol, length)

	var dropped bool
	options := completeOptions

	if fragmented || quoted {
		// A fragment, or a quoted packet that may be truncated (RFC 7915 Section 5.3), does not hold the whole
		// transport payload. It is forwarded with its declared length and only its transport header is translated.
		options = partialOptions
		ipv4.Length = uint16(ipv4HeaderLength + length)

		// RFC 7915 Section 5.5: only the first fragment holds the transport header.
		if ipv4.FragOffset == 0 {
			payload, dropped = translateTransport(protocol, payload, removed, added, quoted)
		}
	} else {
		switch protocol {
		case layers.IPProtocolICMPv6:
			payload, dropped = t.translateICMPv6(payload)
			if payload == nil && !dropped {
				return translated, ErrInvalidICMP
			}
		default:
			// Unknown protocols are forwarded as opaque payloads.
			payload, dropped = translateTransport(protocol, payload, removed, added, false)
		}

		// RFC 7915 Section 5.1: the Identification of an unfragmented packet comes from a generator at the translator.
		ipv4.Id = uint16(nextIdentification.Add(1))
		ipv4.Length = uint16(ipv4HeaderLength + len(payload))
	}

	if dropped {
		return translated, nil
	}

	// When the resulting IPv4 packet is smaller than or equal to 1260
	//  bytes, the translator MUST send the packet with a cleared Don't
	//  Fragment bit.  Otherwise, the packet MUST be sent with the Don't
	//  Fragment bit set.
	if !fragmented && int(ipv4.Length) > ipv4MaximumUnfragmentedSize {
		ipv4.Flags = layers.IPv4DontFragment
	}

	result := serializeTranslatedPacket(options, ipv4.SrcIP, ipv4.DstIP, ipv4, gopacket.Payload(payload))
	if result.Packet == nil {
		return result, fmt.Errorf("%w: failed to serialize IPv4 packet", ErrInvalidPacket)
	}

	return result, nil
}

func isIPv6FragmentExtension(protocol layers.IPProtocol) bool {
	switch protocol {
	case layers.IPProtocolIPv6HopByHop,
		layers.IPProtocolIPv6Routing,
		layers.IPProtocolIPv6Fragment,
		layers.IPProtocolIPv6Destination,
		layers.IPProtocolAH,
		layers.IPProtocol(135), // Mobility Header
		layers.IPProtocol(139), // HIP
		layers.IPProtocol(140): // Shim6
		return true
	default:
		// Unknown future extension headers cannot be identified from the protocol number alone.
		return false
	}
}
