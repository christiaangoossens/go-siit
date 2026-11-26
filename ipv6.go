package siit

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/**
 * RFC 7915 Section 5 (Translating from IPv6 to IPv4)
 */

// TranslateIPv6 translates an IPv6 packet, starting at the IP header, to IPv4. It is like TranslateIPv4 otherwise.
func (t *Translator) TranslateIPv6(packet []byte) (Packet, error) {
	var ip layers.IPv6
	if err := ip.DecodeFromBytes(packet, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}

	return t.translateIPv6(&ip, false)
}

// TranslateIPv6Layer is like TranslateIPv6, for a packet that is already decoded with gopacket.
func (t *Translator) TranslateIPv6Layer(ip *layers.IPv6) (Packet, error) {
	if ip == nil {
		return nil, fmt.Errorf("%w: no IPv6 layer", ErrInvalidPacket)
	}

	return t.translateIPv6(ip, false)
}

// translateIPv6 translates a decoded IPv6 packet to IPv4. quoted is true for the packet inside an ICMPv6 error
// (RFC 7915 Section 5.3).
func (t *Translator) translateIPv6(ip *layers.IPv6, quoted bool) (Packet, error) {
	// Verify that src and dst are both unicast
	if !ip.SrcIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv6 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv6 destination %s is not unicast", ErrUnsupportedDestIP, ip.DstIP)
	}

	// ===
	// Header & checksum validation
	// ===

	// RFC 8200 Section 3 defines a fixed 40-byte IPv6 base header.
	if ip.Version != 6 || len(ip.Contents) < ipv6HeaderLength {
		return nil, fmt.Errorf("%w: invalid IPv6 header", ErrInvalidPacket)
	}

	protocol, payload, offset := ip.NextHeader, ip.Payload, ipv6HeaderLength
	if ip.HopByHop != nil {
		// gopacket already decoded a leading Hop-by-Hop header as part of the IPv6 layer.
		protocol, offset = ip.HopByHop.NextHeader, offset+ip.HopByHop.ActualLength

		// gopacket cuts the payload behind the Hop-by-Hop header to the Payload Length, which includes that header.
		end := int(ip.Length) - ip.HopByHop.ActualLength
		if end < 0 {
			return nil, fmt.Errorf("%w: IPv6 Payload Length is shorter than the Hop-by-Hop header", ErrInvalidPacket)
		}

		payload = payload[:min(len(payload), end)]
	}

	// Get the actual contents, skip over any IPv6 extensions (as per RFC 7915, section 5.1)
	// The IPv6
	//  headers HOPOPT (0), IPv6-Route (43), and IPv6-Opts (60) are
	//  skipped over during processing as they have no meaning in IPv4.
	segmentsLeftOffset := 0
	for protocol == layers.IPProtocolIPv6HopByHop || protocol == layers.IPProtocolIPv6Routing || protocol == layers.IPProtocolIPv6Destination {
		// RFC 8200 Section 4.3: Next Header, then Hdr Ext Len in 8-octet units not including the first 8 octets.
		if len(payload) < 8 || len(payload) < (int(payload[1])+1)*8 {
			return nil, fmt.Errorf("%w: truncated IPv6 extension header", ErrInvalidPacket)
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
			return nil, fmt.Errorf("%w: IPv6 routing header has segments left", ErrInvalidPacket)
		}
		// RFC 7915 Section 5.1: Parameter Problem pointing at Segments Left.
		err := fmt.Errorf("%w: IPv6 routing header has segments left", ErrInvalidPacket)
		return nil, withReply(err, t.generateIPv6ParameterProblem(ip, uint32(segmentsLeftOffset)))
	}

	// ICMPv6 errors may use the IPv4 router address when the outer IPv6 source
	// cannot be mapped to an IPv4 address (RFC 7915 Section 6 with RFC 6791), since they can
	// come from native IPv6 routers. Ordinary packets would be answered to an address we can't map back.
	// RFC 4443 defines types 0-127 as errors. A quoted packet has no such exception: an ICMP error quoting an ICMP error is not translated.
	routerSource := !quoted && protocol == layers.IPProtocolICMPv6 && len(payload) > 0 && payload[0] < 128

	// RFC 6052 Section 3.1: non-global addresses must not be embedded in the Well-Known Prefix.
	if t.isForbiddenIPv6(ip.SrcIP) {
		return nil, fmt.Errorf("%w: IPv6 source %s embeds a non-global IPv4 address", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !routerSource && !t.hasIPv6ToIPv4Mapping(ip.SrcIP) {
		return nil, fmt.Errorf("%w: IPv6 source %s is not mappable", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if t.isForbiddenIPv6(ip.DstIP) {
		return nil, fmt.Errorf("%w: IPv6 destination %s embeds a non-global IPv4 address", ErrUnsupportedDestIP, ip.DstIP)
	}

	// Only the source may fall back to the router address, so the destination must always be mappable.
	if !t.hasIPv6ToIPv4Mapping(ip.DstIP) {
		return nil, fmt.Errorf("%w: IPv6 destination %s is not mappable", ErrUnsupportedDestIP, ip.DstIP)
	}

	if t.isIllegalIPv4Embedded(ip.SrcIP) {
		return nil, fmt.Errorf("%w: IPv6 source %s embeds an illegal IPv4 address", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if t.isIllegalIPv4Embedded(ip.DstIP) {
		return nil, fmt.Errorf("%w: IPv6 destination %s embeds an illegal IPv4 address", ErrUnsupportedDestIP, ip.DstIP)
	}

	// A quoted packet is not sent, so it only needs to be translated.
	if !quoted {
		// Check if the Hop Limit would be 0, if so generate an ICMP Time Exceeded message back to the source of the original packet
		if ip.HopLimit <= 1 {
			return nil, withReply(ErrTimeExceeded, t.generateIPv4TimeExceeded(ip))
		}

		// RFC 8200 Section 8.1: "IPv6 receivers must discard UDP packets containing a zero checksum and should log the
		// error."
		if isZeroUDPChecksum(payload, protocol) {
			return nil, zeroUDPChecksumError(ip.SrcIP, ip.DstIP, payload)
		}

		// Validate transport checksums
		pseudoHeader := ipv6PseudoHeader(ip.SrcIP, ip.DstIP, protocol, len(payload))
		if !validTransportChecksum(pseudoHeader, protocol, payload) {
			return nil, fmt.Errorf("%w: invalid IPv6 transport checksum", ErrInvalidPacket)
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
		SrcIP:      t.mapIPv6ToIPv4(ip.SrcIP),
		DstIP:      t.mapIPv6ToIPv4(ip.DstIP),
	}

	fragmented := protocol == layers.IPProtocolIPv6Fragment
	if fragmented {
		// RFC 8200 Section 4.5 requires an M=1 fragment's payload to be an
		// integer multiple of 8 octets. Reserved fields are ignored on reception.
		moreFragments := len(payload) >= ipv6FragmentHeaderLength && payload[3]&1 != 0
		if len(payload) < ipv6FragmentHeaderLength || (!quoted && moreFragments && (len(payload)-ipv6FragmentHeaderLength)%8 != 0) {
			return nil, fmt.Errorf("%w: invalid IPv6 fragment", ErrInvalidPacket)
		}

		protocol = layers.IPProtocol(payload[0])
		if protocol == layers.IPProtocolICMPv6 {
			return nil, fmt.Errorf("%w: fragmented ICMPv6 packets are unsupported", ErrUnsupportedProtocol)
		}

		ipv4.FragOffset = binary.BigEndian.Uint16(payload[2:4]) >> 3
		ipv4.Id = uint16(binary.BigEndian.Uint32(payload[4:8]))
		ipv4.Protocol = protocol

		if moreFragments {
			ipv4.Flags = layers.IPv4MoreFragments
		}

		payload, offset = payload[ipv6FragmentHeaderLength:], offset+ipv6FragmentHeaderLength

		// RFC 7915 Section 5.1.1 says a Fragment Header followed by an
		// extension header should be dropped and logged because IPv4 cannot represent it.
		if isIPv6FragmentExtension(protocol) {
			return nil, fmt.Errorf("%w: IPv6 fragment followed by extension header %d", ErrUnsupportedProtocol, protocol)
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

		// Only the first fragment holds the transport header.
		if ipv4.FragOffset == 0 {
			payload, dropped = translateTransport(protocol, payload, removed, added, quoted)
		}
	} else {
		switch protocol {
		case layers.IPProtocolICMPv6:
			payload, dropped = t.translateICMPv6(payload)
			if payload == nil && !dropped {
				return nil, ErrInvalidICMP
			}
		default:
			// Unknown protocols are forwarded as opaque payloads.
			payload, dropped = translateTransport(protocol, payload, removed, added, false)
		}

		// RFC 7915 Section 5.1: the Identification of an unfragmented packet comes from a generator at the translator.
		ipv4.Id = t.identifications.next(ipv4.SrcIP, ipv4.DstIP)
		ipv4.Length = uint16(ipv4HeaderLength + len(payload))
	}

	if dropped {
		return nil, nil
	}

	// When the resulting IPv4 packet is smaller than or equal to 1260
	//  bytes, the translator MUST send the packet with a cleared Don't
	//  Fragment bit.  Otherwise, the packet MUST be sent with the Don't
	//  Fragment bit set.
	if !fragmented && int(ipv4.Length) > ipv4MaximumUnfragmentedSize {
		ipv4.Flags = layers.IPv4DontFragment
	}

	result := serializePacket(options, ipv4, payload)
	if result == nil {
		return nil, fmt.Errorf("%w: failed to serialize IPv4 packet", ErrInvalidPacket)
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
