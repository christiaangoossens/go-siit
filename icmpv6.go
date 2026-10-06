package siit

import (
	"encoding/binary"
)

/**
 * RFC 7915 Sections 5.2 and 5.3 (ICMPv6 to ICMPv4)
 */

func (t *Translator) translateICMPv6(payload []byte) ([]byte, bool) {
	if len(payload) < 8 {
		return nil, false
	}

	// ICMPv6 Type and Code are the first two bytes; the checksum occupies bytes 2-3.
	icmpv6Type := payload[0]
	code := payload[1]

	// ICMPv6 has a four-byte fixed header, so its type-specific body starts at byte 4.
	icmpv6Payload := payload[4:]

	switch icmpv6Type {
	case 128:
		// Echo Request
		// Translate to 8
		if code != 0 {
			return nil, false
		}
		return newICMPv4(8, 0, binary.BigEndian.Uint32(icmpv6Payload), payload[8:]), false
	case 129:
		// Echo Reply
		// Translate to 0
		if code != 0 {
			return nil, false
		}
		return newICMPv4(0, 0, binary.BigEndian.Uint32(icmpv6Payload), payload[8:]), false
	case 130, 131, 132:
		// MLD Multicast Listener Query/Report/Done
		// Silently drop
		return nil, true
	case 133, 134, 135, 136, 137:
		// Neighbor Discover messages
		// Silently drop
		return nil, true
	case 1:
		// Destination Unreachable
		var newCode byte

		switch code {
		case 0:
			//  Code 0 (No route to destination):  Set the Code to 1 (Host unreachable).
			newCode = 1
		case 1:
			// Code 1 (Communication with destination administratively prohibited):  Set the Code to 10 (Communication with destination host administratively prohibited).
			newCode = 10
		case 2:
			//  Code 2 (Beyond scope of source address):  Set the Code to 1 (Host unreachable).
			newCode = 1
		case 3:
			// Code 3 (Address unreachable):  Set the Code to 1 (Host unreachable).
			newCode = 1
		case 4:
			//  Code 4 (Port unreachable):  Set the Code to 3 (Port unreachable).
			newCode = 3
		default:
			// Other Code values:  Silently drop.
			return nil, true
		}

		return t.translateICMPv6Error(payload, 3, newCode, 0)
	case 2:
		// Packet Too Big
		// Translate to an ICMPv4 Destination
		//  Unreachable (Type 3) with Code 4
		// RFC 4443 Section 3.2: the Code is ignored by the receiver.
		// RFC 4443 stores Packet Too Big's four-byte MTU at the start of its body.
		// RFC 7915 Section 5.2: the MTU loses the difference between the IPv6 and IPv4 header, limited by our own IPv6 MTU.
		mtu := min(max(binary.BigEndian.Uint32(icmpv6Payload), ipv6MinimumMTU), t.MTU) - (ipv6HeaderLength - ipv4HeaderLength)
		return t.translateICMPv6Error(payload, 3, 4, min(mtu, 0xffff))
	case 3:
		// Time Exceeded
		if code > 1 {
			return nil, false
		}
		return t.translateICMPv6Error(payload, 11, code, 0)
	case 4:
		// Parameter Problem (Type 4)
		switch code {
		case 0:
			// Code 0 (Erroneous header field encountered):
			// RFC 4443 stores Parameter Problem's four-byte pointer at the start of its body.
			pointer, ok := t.mapParameterPointer(binary.BigEndian.Uint32(icmpv6Payload), false)
			if !ok {
				return nil, true
			}

			// Set to Type 12,
			// Code 0, and update the pointer as defined in Figure 6.
			// RFC 792: the pointer of an ICMPv4 Parameter Problem is the first octet after the checksum.
			return t.translateICMPv6Error(payload, 12, 0, pointer<<24)
		case 1:
			// Code 1 (Unrecognized Next Header type encountered)
			// Translate
			// this to an ICMPv4 protocol unreachable (Type 3, Code 2).
			return t.translateICMPv6Error(payload, 3, 2, 0)
		case 2:
			// Code 2 (Unrecognized IPv6 option encountered):  Silently drop.
			return nil, true
		default:
			// Other Code values: silently drop.
			return nil, true
		}
	default:
		// Other ICMPv6 information & error types:  Silently drop.
		return nil, true
	}
}

// translateICMPv6Error builds the ICMPv4 error around the translated quote, RFC 4884 extensions go to Types 3 and 11.
func (t *Translator) translateICMPv6Error(payload []byte, icmpType, code byte, rest uint32) ([]byte, bool) {
	data, extension := payload[icmpErrorHeaderLength:], []byte(nil)
	if icmpType == 3 || icmpType == 11 {
		data, extension = splitICMPExtension(data, int(payload[4]), 8)
	}

	quote := t.translateQuotedIPv6(data)
	if quote == nil {
		return nil, true
	}

	data, words := joinICMPQuote(quote, extension, ipv4ICMPErrorPayloadMaximum, 4)
	return newICMPv4(icmpType, code, rest|uint32(words)<<16, data), false
}
