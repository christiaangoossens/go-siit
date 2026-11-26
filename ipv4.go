package siit

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Section 4 (Translating from IPv4 to IPv6)

// TranslateIPv4 translates an IPv4 packet, starting at the IP header, to IPv6. The packet is not modified or retained.
//
// The result is empty when the packet is dropped (nil error) or rejected (non-nil error). A rejected packet that the
// translator answers carries the answer in a *TranslationError.
func (t *Translator) TranslateIPv4(packet []byte) (Packet, error) {
	var ip layers.IPv4
	if err := ip.DecodeFromBytes(packet, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}

	return t.translateIPv4(&ip, false)
}

// TranslateIPv4Layer is like TranslateIPv4, for a packet that is already decoded with gopacket. The layer must come
// from decoding, so that its Contents and Payload match its fields. It is not modified.
func (t *Translator) TranslateIPv4Layer(ip *layers.IPv4) (Packet, error) {
	if ip == nil {
		return nil, fmt.Errorf("%w: no IPv4 layer", ErrInvalidPacket)
	}

	return t.translateIPv4(ip, false)
}

// translateIPv4 translates a decoded IPv4 packet to IPv6. quoted is true for the packet inside an ICMPv4 error
// (RFC 7915 Section 4.3).
func (t *Translator) translateIPv4(ip *layers.IPv4, quoted bool) (Packet, error) {
	// ===
	// Header validation
	// ===

	// RFC 791 Section 3.1 defines a 20-byte minimum IPv4 header and requires
	// Total Length to include that header; reject packets that cannot be parsed.
	if ip.Version != 4 || ip.IHL < 5 || len(ip.Contents) < int(ip.IHL)*4 || ip.Length < uint16(ip.IHL)*4 {
		return nil, fmt.Errorf("%w: invalid IPv4 header", ErrInvalidPacket)
	}

	// A packet that is sent must be complete. gopacket replaces a Total Length of 0 with the length of the data, so
	// the field is compared with the header bytes too.
	if !quoted && (len(ip.Payload) != int(ip.Length)-int(ip.IHL)*4 || binary.BigEndian.Uint16(ip.Contents[2:4]) != ip.Length) {
		return nil, fmt.Errorf("%w: IPv4 Total Length %d does not match the packet", ErrInvalidPacket, ip.Length)
	}

	// Verify that src and dst are both unicast
	if !ip.SrcIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv4 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv4 destination %s is not unicast", ErrUnsupportedDstIP, ip.DstIP)
	}

	// RFC 6052 Section 3.1: non-global addresses must not be embedded in the Well-Known Prefix.
	if t.isForbiddenIPv4(ip.SrcIP) {
		return nil, fmt.Errorf("%w: non-global IPv4 source %s cannot use the Well-Known Prefix", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if t.isForbiddenIPv4(ip.DstIP) {
		return nil, fmt.Errorf("%w: non-global IPv4 destination %s cannot use the Well-Known Prefix", ErrUnsupportedDstIP, ip.DstIP)
	}

	// IPv6 extension headers have no IPv4 equivalent. Forwarding their protocol numbers would make the receiver
	// parse the payload as an extension header.
	switch ip.Protocol {
	case layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Fragment, layers.IPProtocolIPv6Destination:
		return nil, fmt.Errorf("%w: IPv4 protocol %d is an IPv6 extension header", ErrUnsupportedProtocol, ip.Protocol)
	}

	// ===
	// Checksum validation
	// ===

	fragmented := ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0

	// A quoted packet is not sent, so it only needs to be translated.
	if !quoted {
		if !validIPv4HeaderChecksum(ip) {
			return nil, fmt.Errorf("%w: invalid IPv4 header checksum", ErrInvalidPacket)
		}

		maxIPv4PacketLength := t.maxIPv4PacketLength(fragmented)
		if uint32(ip.Length) > maxIPv4PacketLength {
			return nil, fmt.Errorf("%w: IPv4 packet length %d exceeds %d bytes", ErrPacketOversized, ip.Length, maxIPv4PacketLength)
		}

		icmpError := ip.Protocol == layers.IPProtocolICMPv4 && ip.FragOffset == 0 && len(ip.Payload) > 0 && isICMPv4ErrorType(ip.Payload[0])

		// RFC 7915 Section 4.1 (MUST): "the translator (as any router) MUST check for zero and send the ICMPv4 'TTL
		// Exceeded' or ICMPv6 'Hop Limit Exceeded' error."
		//
		// The TTL is decremented before the translation, so the error goes back to the sender as ICMPv4.
		if ip.TTL <= 1 {
			// RFC 1812 Section 4.3.2.7 (MUST NOT): "An ICMP error message MUST NOT be sent as the result of receiving"
			//
			// Of that list, an ICMP error or a fragment other than the first can get here.
			if icmpError || ip.FragOffset != 0 {
				return nil, ErrTimeExceeded
			}

			return nil, withReply(ErrTimeExceeded, t.generateIPv4TimeExceeded(ip))
		}

		// If any IPv4 options are present in the IPv4 packet, they MUST be
		// ignored and the packet translated normally; there is no attempt to
		// translate the options.  However, if an unexpired source route option
		// is present, then the packet MUST instead be discarded, and an ICMPv4
		// "Destination Unreachable, Source Route Failed" (Type 3, Code 5) error
		// message SHOULD be returned to the sender.
		for _, option := range ip.Options {
			// RFC 7915 Section 4.1 says an unexpired IPv4 source route MUST cause
			// the packet to be discarded because IPv4 options are not translated.
			// RFC 791 Section 3.1: the route is used up once its pointer lies beyond the option.
			if (option.OptionType == 131 || option.OptionType == 137) && len(option.OptionData) > 0 && option.OptionData[0] <= option.OptionLength {
				// RFC 1812 Section 4.3.2.7: no ICMP error in reply to an ICMP error, so such a packet is only discarded.
				if icmpError {
					return nil, fmt.Errorf("%w in an ICMPv4 error", ErrSourceRouteFailed)
				}

				return nil, withReply(ErrSourceRouteFailed, t.generateIPv4SourceRouteFailed(ip))
			}
		}

		// Check the transport checksum (skip if fragment)
		// RFC 768: IPv4 UDP may omit its checksum.
		pseudoHeader := ipv4PseudoHeader(ip.SrcIP, ip.DstIP, ip.Protocol, len(ip.Payload))
		if !fragmented && !isZeroUDPChecksum(ip.Payload, ip.Protocol) && !validTransportChecksum(pseudoHeader, ip.Protocol, ip.Payload) {
			return nil, fmt.Errorf("%w: invalid IPv4 transport checksum", ErrInvalidPacket)
		}
	}

	// ===
	// Construction
	// ===

	ttl := ip.TTL - 1
	if quoted {
		// For quoted packets, we do not decrement the TTL/Hop Limit, as it is already decremented in the outer packet.
		ttl = ip.TTL
	}

	// Create a new IPv6 packet that matches the IPv4 Packet without any payload
	protocol := ip.Protocol
	ipv6 := &layers.IPv6{
		Version:      6,
		TrafficClass: ip.TOS,
		FlowLabel:    0, // Flow Label:  0 (all zero bits)
		NextHeader:   protocol,
		HopLimit:     ttl,
		SrcIP:        t.mapIPv4ToIPv6(ip.SrcIP),
		DstIP:        t.mapIPv4ToIPv6(ip.DstIP),
	}

	// ICMP has some special translation rules and validations
	if protocol == layers.IPProtocolICMPv4 {
		if fragmented {
			// RFC 7915 Section 1.2 does not translate fragmented ICMP packets.
			return nil, fmt.Errorf("%w: fragmented ICMPv4 packets are unsupported", ErrUnsupportedProtocol)
		}

		// For ICMPv4 (1), it is changed to ICMPv6 (58).
		protocol = layers.IPProtocolICMPv6
		ipv6.NextHeader = protocol
	}

	// ===
	// Transport payload
	// ===

	length := int(ip.Length) - int(ip.IHL)*4
	removed := ipv4PseudoHeader(ip.SrcIP, ip.DstIP, ip.Protocol, length)
	added := ipv6PseudoHeader(ipv6.SrcIP, ipv6.DstIP, protocol, length)

	var payload []byte
	var dropped bool
	options := completeOptions

	if fragmented || quoted {
		// A fragment, or a quoted packet that may be truncated (RFC 7915 Section 4.3), does not hold the whole
		// transport payload. It is forwarded with its declared length and only its transport header is translated.
		options = partialOptions
		ipv6.Length = uint16(length)
		payload = ip.Payload

		// RFC 7915 Section 4.5: "the translator SHOULD drop the packet and generate a system management event that
		// specifies at least the IP addresses and port numbers in the packet."
		if fragmented && !quoted && ip.FragOffset == 0 && isZeroUDPChecksum(payload, ip.Protocol) {
			return nil, zeroUDPChecksumError(ip.SrcIP, ip.DstIP, payload)
		}

		// Only the first fragment holds the transport header.
		if ip.FragOffset == 0 {
			payload, dropped = translateTransport(ip.Protocol, payload, removed, added, quoted)
		}

		if fragmented {
			// RFC 7915 Section 4.1 requires an IPv6 Fragment Header for an already
			// fragmented IPv4 packet and copies its offset, M flag, and identifier.
			ipv6.NextHeader = layers.IPProtocolIPv6Fragment
			ipv6.Length += ipv6FragmentHeaderLength
			fragmentHeader := make([]byte, ipv6FragmentHeaderLength)
			fragmentHeader[0] = byte(protocol)
			binary.BigEndian.PutUint16(fragmentHeader[2:4], ip.FragOffset<<3)

			if ip.Flags&layers.IPv4MoreFragments != 0 {
				fragmentHeader[3] |= 1
			}

			// The low-order 16 bits copied from the
			// Identification field in the IPv4 header.  The high-order 16
			// bits set to zero.
			binary.BigEndian.PutUint32(fragmentHeader[4:8], uint32(ip.Id))
			payload = append(fragmentHeader, payload...)
		}
	} else {
		switch {
		case protocol == layers.IPProtocolIGMP:
			// IGMP should be silently dropped as they are single hop.
			return nil, nil
		case protocol == layers.IPProtocolICMPv6:
			payload, dropped = t.translateICMPv4(ipv6, ip.Payload)
			if payload == nil && !dropped {
				return nil, ErrInvalidICMP
			}
		case isZeroUDPChecksum(ip.Payload, protocol):
			// RFC 7915 Section 4.5: a UDP datagram without checksum gets one, as IPv6 requires it.
			payload = slices.Clone(ip.Payload)
			checksum := internetChecksum(added, payload)
			if checksum == 0 {
				checksum = 0xffff
			}
			binary.BigEndian.PutUint16(payload[6:], checksum)
		default:
			// RFC 7915 Section 4.5 requires unsupported transport protocols to be forwarded unchanged.
			payload, dropped = translateTransport(protocol, ip.Payload, removed, added, false)
		}
	}

	if dropped {
		return nil, nil
	}

	result := serializePacket(options, ipv6, payload)
	if result == nil {
		return nil, fmt.Errorf("%w: failed to serialize IPv6 packet", ErrInvalidPacket)
	}

	return result, nil
}
