package siit

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"
)

/**
 * RFC 7915 Sections 4.2 and 4.3 (ICMPv4 to ICMPv6)
 */

// RFC 1191 Table 7-1: the MTU plateaus used when a router reports no next-hop MTU.
var mtuPlateaus = []uint32{65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68}

func (t *Translator) translateICMPv4(ip *layers.IPv6, payload []byte) ([]byte, bool) {

	if len(payload) < 8 {
		return nil, false
	}

	// ICMPv4's fixed header is Type, Code, Checksum, Identifier, Sequence;
	// these offsets come from RFC 792's 8-byte header layout.
	icmpv4Type := payload[0] // Type
	icmpv4Code := payload[1] // Code
	// Checksum occupies bytes 2-3 and is recomputed during serialization.
	identifier := binary.BigEndian.Uint16(payload[4:6])
	sequence := binary.BigEndian.Uint16(payload[6:8])

	// The ICMPv4 header is 8 bytes; everything after it is the inner packet or echo data.
	icmpv4Payload := payload[8:]

	var newType uint8
	switch icmpv4Type {
	case 8:
		if icmpv4Code != 0 {
			return nil, false
		}
		newType = 128
	case 0:
		if icmpv4Code != 0 {
			return nil, false
		}
		newType = 129
	case 15, 16:
		// Information Request/Reply (Type 15 and Type 16):  Obsoleted in ICMPv6. Silently drop.
		return nil, true
	case 13, 14:
		// Timestamp Request/Reply (Type 13 and Type 14):  Obsoleted in ICMPv6. Silently drop.
		return nil, true
	case 17, 18:
		// Address Mask Request/Reply (Type 17 and Type 18):  Obsoleted in ICMPv6. Silently drop.
		return nil, true
	case 9:
		// Router Advertisement (Type 9):  Single-hop message. Silently drop.
		return nil, true
	case 10:
		// Router Solicitation (Type 10):  Single-hop message. Silently drop.
		return nil, true
	case 3:
		// ICMP Errors: Destination Unreachable
		newCode := byte(0)
		switch icmpv4Code {
		case 0, 1:
			// Code 0, 1 (Net Unreachable, Host Unreachable):  Set the Code
			//   to 0 (No route to destination).
			newCode = 0
		case 2:
			// Code 2 (Protocol Unreachable):  Translate to an ICMPv6
			//   Parameter Problem (Type 4, Code 1) and make the Pointer
			//   point to the IPv6 Next Header field.
			return t.translateICMPv4Error(ip, payload, 4, 1, 6)
		case 3:
			// Code 3 (Port Unreachable):  Set the Code to 4 (Port
			//   unreachable).
			newCode = 4
		case 4:
			// Code 4 (Fragmentation Needed and DF was Set)
			// Translate to
			//   an ICMPv6 Packet Too Big message (Type 2) with Code set
			//   to 0.
			mtu := uint32(sequence)
			if mtu == 0 && len(icmpv4Payload) >= 4 {
				// RFC 1191: the router reports no MTU, so use the largest plateau below the length of the original datagram.
				original := uint32(binary.BigEndian.Uint16(icmpv4Payload[2:4]))
				for _, plateau := range mtuPlateaus {
					if plateau < original {
						mtu = plateau
						break
					}
				}
			}
			mtu = min(mtu+ipv4HeaderLength, t.MTU)
			if mtu < ipv6MinimumMTU {
				// When translating, set the minimum to the IPv6 minimum.
				mtu = ipv6MinimumMTU
			}
			return t.translateICMPv4Error(ip, payload, 2, 0, mtu)
		case 5:
			// Code 5 (Source Route Failed):  Set the Code to 0 (No route
			//   to destination).
			newCode = 0
		case 6, 7, 8:
			// Code 6, 7, 8 (Destination Network/Host/Protocol Unknown):
			// Set the Code to 0 (No route to destination).
			newCode = 0
		case 9, 10:
			// Code 9, 10 (Destination Network/Host Administratively Prohibited):
			// Set the Code to 1
			//   (Communication with destination administratively
			//   prohibited).
			newCode = 1
		case 11, 12:
			// Code 11, 12:  Set the Code to 0 (No route to destination).
			newCode = 0
		case 13:
			// Code 13 (Communication Administratively Prohibited):  Set
			//   the Code to 1 (Communication with destination
			//   administratively prohibited).
			newCode = 1
		case 14:
			// Code 14 (Host Precedence Violation):  Silently drop.
			return nil, true
		case 15:
			// Code 15 (Precedence cutoff in effect):  Set the Code to 1
			//   (Communication with destination administratively
			//   prohibited).
			newCode = 1
		default:
			// Other Code values:  Silently drop.
			return nil, true
		}

		// Set type to 1
		return t.translateICMPv4Error(ip, payload, 1, newCode, 0)
	case 5:
		// Redirect (Type 5):  Single-hop message.  Silently drop.
		return nil, true
	case 6:
		// Alternative Host Address (Type 6):  Silently drop.
		return nil, true
	case 4:
		// Source Quench (Type 4):  Obsoleted in ICMPv6.  Silently drop.
		return nil, true
	case 11:
		// Time Exceeded (Type 11):  Translate to ICMPv6 Time Exceeded (Type 3).
		// The Code is unchanged.
		return t.translateICMPv4Error(ip, payload, 3, icmpv4Code, 0)

	case 12:
		// Code 1 (Missing a required option):  Silently drop.
		// Other Code values:  Silently drop.
		if icmpv4Code == 1 || icmpv4Code > 2 {
			return nil, true
		}

		// RFC 792: the pointer of a Parameter Problem is the first octet after the checksum.
		mapped, ok := t.mapParameterPointer(uint32(payload[4]), true)
		if !ok {
			return nil, true
		}

		// Set the Type to 4
		return t.translateICMPv4Error(ip, payload, 4, 0, mapped)
	default:
		// Unknown ICMPv4 types:  Silently drop.
		return nil, true
	}

	// Echo Request/Reply keep their Identifier, Sequence and data.
	return newICMPv6(ip, newType, 0, uint32(identifier)<<16|uint32(sequence), icmpv4Payload), false
}

// translateICMPv4Error builds the ICMPv6 error around the translated quote, RFC 4884 extensions go to Types 1 and 3.
func (t *Translator) translateICMPv4Error(ip *layers.IPv6, payload []byte, icmpType, code byte, rest uint32) ([]byte, bool) {
	data, extension := payload[icmpErrorHeaderLength:], []byte(nil)
	if icmpType == 1 || icmpType == 3 {
		data, extension = splitICMPExtension(data, int(payload[5]), 4)
	}

	quote := t.translateQuotedIPv4(data)
	if quote == nil {
		return nil, true
	}

	data, words := joinICMPQuote(quote, extension, ipv6ICMPErrorPayloadMaximum, 8)
	return newICMPv6(ip, icmpType, code, rest|uint32(words)<<24, data), false
}
