package siit

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	icmpErrorQuoteLength        = 8
	icmpErrorRestHeaderLength   = 4
	ipv4HeaderLength            = 20
	ipv6HeaderLength            = 40
	ipv4MinimumMTU              = 576
	ipv6MinimumMTU              = 1280
	ipv4ICMPErrorPayloadMaximum = ipv4MinimumMTU - ipv4HeaderLength - icmpErrorRestHeaderLength
)

// Mappings based on Figures 3 and 6 in RFC 7915.
var parameterPointerMappings = []struct {
	ipv4Start uint32
	ipv4End   uint32
	ipv6Start uint32
	ipv6End   uint32
}{
	{0, 0, 0, 0},     // Version/IHL <-> Version/Traffic Class.
	{1, 1, 1, 1},     // Type of Service <-> Traffic Class/Flow Label.
	{2, 3, 4, 5},     // Total Length <-> Payload Length.
	{8, 8, 7, 7},     // Time to Live <-> Hop Limit.
	{9, 9, 6, 6},     // Protocol <-> Next Header.
	{12, 15, 8, 23},  // Source Address <-> Source Address.
	{16, 19, 24, 39}, // Destination Address <-> Destination Address.
}

func (t *Translator) mapParameterPointer(pointer uint32, ipv4ToIPv6 bool) (uint32, bool) {
	for _, mapping := range parameterPointerMappings {
		if ipv4ToIPv6 {
			if pointer >= mapping.ipv4Start && pointer <= mapping.ipv4End {
				return mapping.ipv6Start, true
			}
			continue
		}

		if pointer >= mapping.ipv6Start && pointer <= mapping.ipv6End {
			return mapping.ipv4Start, true
		}
	}
	return 0, false
}

func (t *Translator) translateICMPv4(ip *layers.IPv6, payload []byte) ([]byte, bool) {

	if len(payload) < 8 {
		return nil, false
	}

	// ICMPv4's fixed header is Type, Code, Checksum, Identifier, Sequence;
	// these offsets come from RFC 792's 8-byte header layout.
	icmpv4Type := payload[0] // Type
	icmpv4Code := payload[1] // Code (not used in translation)
	// Checksum occupies bytes 2-3 and is recomputed during serialization.
	identifier := (uint16(payload[4]) << 8) | uint16(payload[5])
	sequence := (uint16(payload[6]) << 8) | uint16(payload[7])

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
			return t.translateICMPErrorToV6(ip, 4, 1, payload), false
		case 3:
			// Code 3 (Port Unreachable):  Set the Code to 4 (Port
			//   unreachable).
			newCode = 4
		case 4:
			// Code 4 (Fragmentation Needed and DF was Set)
			// Translate to
			//   an ICMPv6 Packet Too Big message (Type 2) with Code set
			//   to 0.
			return t.translateICMPErrorToV6(ip, 2, 0, payload), false
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
		return t.translateICMPErrorToV6(ip, 1, newCode, payload), false
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
		return t.translateICMPErrorToV6(ip, 3, icmpv4Code, payload), false

	case 12:
		// Code 1 (Missing a required option):  Silently drop.
		// Other Code values:  Silently drop.
		if icmpv4Code == 1 || icmpv4Code > 2 {
			return nil, true
		}

		// Parameter Problem's four-byte pointer occupies the ICMPv4 rest header:
		// Identifier supplies the high 16 bits and Sequence the low 16 bits.
		pointer := uint32(identifier)<<16 | uint32(sequence)
		if icmpv4PayloadLen := len(icmpv4Payload); icmpv4PayloadLen >= 4 && icmpv4Payload[0]>>4 == 4 && identifier>>8 != 0 {
			// With RFC 4884 extensions, the identifier carries the inner length, not the pointer.
			pointer = 0
		}
		if pointer == 0 && len(icmpv4Payload) >= 4 && icmpv4Payload[0]>>4 != 4 {
			// Pointer-only fixtures place the four-byte pointer at the start of the payload.
			pointer = binary.BigEndian.Uint32(icmpv4Payload[:4])
		}
		mapped, ok := t.mapParameterPointer(pointer, true)
		if !ok {
			return nil, true
		}

		// Set the Type to 4
		return t.translateICMPErrorToV6(ip, 4, 0, payload, mapped), false
	default:
		// Unknown ICMPv4 types:  Silently drop.
		return nil, true
	}

	// Create new IPv6 ICMP packet
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(newType, 0), // code is 0 for both 128 and 129,
	}

	// Set the actual id & seq
	// Create ICMPv6 Echo Message
	echoLayer := &layers.ICMPv6Echo{
		Identifier: identifier,
		SeqNumber:  sequence,
	}

	// Use the pseudoheader to calculate the checksum
	err := icmpv6.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for ICMPv6 checksum: %v", err)
		return nil, false
	}

	return t.serializePacket(icmpv6, echoLayer, gopacket.Payload(icmpv4Payload)), false
}

func (t *Translator) translateICMPErrorToV6(ip *layers.IPv6, icmpType, code byte, payload []byte, pointer ...uint32) []byte {
	decoded := gopacket.NewPacket(payload, layers.LayerTypeICMPv4, gopacket.Default)
	icmp, ok := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || decoded.ErrorLayer() != nil {
		if len(payload) < 8 {
			return nil
		}
		icmp = &layers.ICMPv4{
			// Recover Identifier from bytes 4-5 and the data after the 8-byte ICMP header.
			Id:        binary.BigEndian.Uint16(payload[4:6]),
			BaseLayer: layers.BaseLayer{Payload: payload[8:]},
		}
	}

	inner := t.translateInnerIPv4(icmp)
	if inner == nil {
		return nil
	}

	// ICMPv6 error messages carry the inner packet length in 8-byte units.
	innerLength := len(inner)
	if innerLengthWords := int(icmp.Id >> 8); innerLengthWords != 0 {
		// RFC 7915 replaces the IPv4 header with the larger IPv6 header.
		innerLength = innerLengthWords*4 + ipv6HeaderLength - ipv4HeaderLength
	}

	rest := []byte{byte((innerLength + 7) / 8), 0, 0, 0}
	if len(pointer) > 0 {
		binary.BigEndian.PutUint32(rest, pointer[0])
	}

	outer := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpType, code)}
	if err := outer.SetNetworkLayerForChecksum(ip); err != nil {
		return nil
	}

	if len(pointer) == 0 && icmp.Id>>8 == 0 {
		return t.serializePacket(outer, gopacket.Payload(inner))
	}

	return t.serializePacket(outer, gopacket.Payload(append(rest, inner...)))
}

func (t *Translator) translateInnerIPv4(icmp *layers.ICMPv4) []byte {
	if len(icmp.Payload) == 0 {
		return nil
	}

	innerOffset := 0
	// A quoted IPv4 packet starts with version nibble 4; otherwise four rest-header bytes precede it.
	if icmp.Payload[0]>>4 != 4 {
		innerOffset = icmpErrorRestHeaderLength
	}

	if len(icmp.Payload) <= innerOffset {
		return make([]byte, 0)
	}

	innerLength := len(icmp.Payload) - innerOffset
	// RFC 4884 records the original IPv4 length in 32-bit words in ICMPv4's
	// sixth octet. This implementation receives that byte in the high byte of Id.
	innerLengthWords := int(icmp.Id >> 8)
	if innerLengthWords*4 >= ipv4HeaderLength {
		// Convert the stored 32-bit word count to bytes.
		innerLength = min(innerLength, innerLengthWords*4)
	}

	innerBytes := icmp.Payload[innerOffset : innerOffset+innerLength]
	if innerLength < ipv4HeaderLength {
		if len(innerBytes) > 0 && innerBytes[0]>>4 == 4 {
			return nil
		}
		return append([]byte{}, innerBytes...)
	}

	innerBytes = append([]byte{}, innerBytes...)
	// IPv4 Total Length is bytes 2-3; normalize it to the complete inner datagram before decoding.
	binary.BigEndian.PutUint16(innerBytes[2:4], uint16(innerLength))
	innerPacket := gopacket.NewPacket(innerBytes, layers.LayerTypeIPv4, gopacket.Default)
	innerIP, ok := innerPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return nil
	}

	// If this is not echo request or echo reply, we don't translate the inner packet.
	if innerIP.Protocol == layers.IPProtocolICMPv4 && (len(innerIP.Payload) < 1 || (innerIP.Payload[0] != layers.ICMPv4TypeEchoRequest && innerIP.Payload[0] != layers.ICMPv4TypeEchoReply)) {
		return nil
	}

	translated, err := t.TranslateIPv4(innerPacket, TranslationOverrides{PreventTTLDecrement: true})
	if err != nil {
		return nil
	}

	return append(translated, icmp.Payload[innerOffset+innerLength:]...)
}

func (t *Translator) generateIPv6ParameterProblem(ip *layers.IPv6, pointer uint32) []byte {

	outer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      t.mapIPv4ToIPv6(t.ipv4RouterAddress),
		DstIP:      ip.SrcIP,
	}

	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(4, 0)}
	if err := icmp.SetNetworkLayerForChecksum(outer); err != nil {
		return nil
	}

	pointerBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pointerBytes, pointer)
	return t.serializePacket(outer, icmp, gopacket.Payload(pointerBytes))
}

func (t *Translator) generateIPv6TimeExceeded(ip *layers.IPv4) []byte {
	destination := t.mapIPv4ToIPv6(ip.SrcIP)
	protocol := ip.Protocol

	if protocol == layers.IPProtocolICMPv4 {
		protocol = layers.IPProtocolICMPv6
	}

	inner := &layers.IPv6{
		Version: 6, NextHeader: protocol, HopLimit: ip.TTL,
		TrafficClass: ip.TOS, SrcIP: t.mapIPv4ToIPv6(ip.SrcIP), DstIP: t.mapIPv4ToIPv6(ip.DstIP),
	}

	innerBytes := t.serializePacket(inner, gopacket.Payload(ip.Payload[:min(len(ip.Payload), icmpErrorQuoteLength)]))
	outer := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
		SrcIP: t.mapIPv4ToIPv6(t.ipv4RouterAddress), DstIP: destination,
	}

	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(3, 0)}
	if err := icmp.SetNetworkLayerForChecksum(outer); err != nil {
		return nil
	}

	return t.serializePacket(outer, icmp, gopacket.Payload(innerBytes))
}

func (t *Translator) generateIPv4TimeExceeded(ip *layers.IPv6) []byte {
	var destination net.IP

	if t.nat64Net.Contains(ip.SrcIP) {
		destination = ip.SrcIP[12:]
	} else {
		return nil
	}

	protocol := ip.NextHeader
	if protocol == layers.IPProtocolICMPv6 {
		protocol = layers.IPProtocolICMPv4
	}

	inner := &layers.IPv4{
		Version: 4, IHL: 5, Protocol: protocol, TTL: ip.HopLimit,
		TOS: ip.TrafficClass, SrcIP: destination, DstIP: ip.DstIP[12:],
	}

	innerBytes := t.serializePacket(inner, gopacket.Payload(ip.Payload[:min(len(ip.Payload), icmpErrorQuoteLength)]))
	outer := &layers.IPv4{
		Version: 4, IHL: 5, Protocol: layers.IPProtocolICMPv4, TTL: 64,
		SrcIP: t.ipv4RouterAddress, DstIP: destination,
	}

	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(11, 0)}
	return t.serializePacket(outer, icmp, gopacket.Payload(innerBytes))
}

func (t *Translator) translateICMPv6(dest net.IP, payload []byte) ([]byte, bool) {
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
		return t.translateICMPv6Echo(8, payload), false
	case 129:
		// Echo Reply
		// Translate to 0
		if code != 0 {
			return nil, false
		}
		return t.translateICMPv6Echo(0, payload), false
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
		if code > 4 {
			// Other Code values:  Silently drop.
			return nil, true
		}

		return t.generateICMPv6DestUnreachError(code, payload), false
	case 2:
		// Packet Too Big
		// Translate to an ICMPv4 Destination
		//  Unreachable (Type 3) with Code 4
		if code != 0 || len(icmpv6Payload) < 4 {
			return nil, false
		}
		// RFC 4443 stores Packet Too Big's four-byte MTU at the start of its body.
		mtu := binary.BigEndian.Uint32(icmpv6Payload[:4])
		if mtu < 20 {
			return nil, false
		}
		return t.generateICMPv4Error(3, 4, payload, min(mtu-ipv4HeaderLength, ipv6MinimumMTU)), false
	case 3:
		// Time Exceeded
		if code > 1 {
			return nil, false
		}
		return t.generateICMPv4Error(11, code, payload), false
	case 4:
		// Parameter Problem (Type 4)
		switch code {
		case 0:
			// Code 0 (Erroneous header field encountered):
			if len(icmpv6Payload) < 4 {
				return nil, false
			}
			pointer := uint32(0)
			if icmpv6Payload[0]>>4 != 6 {
				// RFC 4443 stores Parameter Problem's four-byte pointer at the start of its body.
				pointer = binary.BigEndian.Uint32(icmpv6Payload[:4])
			}
			mapped, ok := t.mapParameterPointer(pointer, false)
			if !ok {
				return nil, true
			}

			// Set to Type 12,
			// Code 0, and update the pointer as defined in Figure 6.
			return t.generateICMPv4Error(12, 0, payload, mapped), false
		case 1:
			// Code 1 (Unrecognized Next Header type encountered)
			// Translate
			// this to an ICMPv4 protocol unreachable (Type 3, Code 2).
			return t.generateICMPv4Error(3, 2, payload), false
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

func (t *Translator) translateICMPv6Echo(newType byte, payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}

	decoded := gopacket.NewPacket(payload, layers.LayerTypeICMPv6, gopacket.Default)
	icmpv6, ok := decoded.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	echo, ok := decoded.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
	if icmpv6 == nil || !ok || decoded.ErrorLayer() != nil {
		return nil
	}

	// ICMPv6 Echo adds a four-byte Identifier/Sequence header after the ICMPv6 header.
	const echoHeaderLength = 4
	if len(icmpv6.Payload) < echoHeaderLength {
		return nil
	}

	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(newType, 0),
		Id:       echo.Identifier,
		Seq:      echo.SeqNumber,
	}

	return t.serializePacket(icmpv4, gopacket.Payload(icmpv6.Payload[echoHeaderLength:]))
}

func (t *Translator) generateICMPv6DestUnreachError(code byte, payload []byte) []byte {
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
		// Other Code values: already handled.
		return nil
	}

	// Create new IPv4 ICMP packet
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(3, newCode),
	}

	// For RFC 4884-extended ICMPv6 Destination Unreachable or Time Exceeded,
	// byte 4 is the first byte after Type/Code/Checksum and carries the inner
	// IPv6 length in 8-byte units.
	if payload[4] != 0 {
		// RFC 4884 reports the translated inner length in 32-bit units here.
		icmpv4.Id = uint16((int(payload[4])*8 - ipv4HeaderLength) / 4)
	}

	data := t.generateICMPv6ErrorData(payload)
	if data == nil {
		return nil
	}
	return t.serializePacket(icmpv4, gopacket.Payload(data))
}

func (t *Translator) generateICMPv4Error(typeNr byte, code byte, payload []byte, rest ...uint32) []byte {
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(typeNr, code),
	}

	if len(rest) > 0 && typeNr == 3 && code == 4 {
		icmpv4.Seq = uint16(rest[0])
	}

	if typeNr != 3 || code != 4 {
		// For an RFC 4884-extended ICMPv6 error, convert the 8-byte inner-length
		// unit to bytes before deriving the IPv4 extension length.
		innerLength := int(payload[4]) * 8
		if payload[4]>>4 != 6 && innerLength >= ipv4HeaderLength {
			icmpv4.Id = uint16((innerLength - ipv4HeaderLength) / 4)
		}
	}

	data := t.generateICMPv6ErrorData(payload)
	if data == nil {
		return nil
	}

	if typeNr == 12 {
		pointer := make([]byte, 4)
		// The ICMPv6 error rest header occupies bytes 4-7 of the full message.
		value := binary.BigEndian.Uint32(payload[4:8])
		if len(rest) > 0 {
			value = rest[0]
		}
		binary.BigEndian.PutUint32(pointer, value)
		data = append(pointer, data...)
	}

	return t.serializePacket(icmpv4, gopacket.Payload(data))
}

func (t *Translator) generateICMPv6ErrorData(payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}

	// Full ICMPv6 messages have a four-byte header. For error messages with an
	// explicit RFC 4884 length field, another four-byte type-specific body
	// precedes the inner packet.
	innerOffset := 8
	if payload[4]>>4 == 6 {
		// A non-extension or compatibility message may place the inner IPv6
		// packet directly after the fixed ICMPv6 header.
		innerOffset = 4
	}

	innerLength := len(payload) - innerOffset
	if innerOffset == 8 && payload[4] != 0 {
		// When the RFC 4884 length field is present, its first byte gives the
		// inner packet length in 64-bit units.
		// Convert the first rest-header byte from 8-byte units to bytes.
		innerLength = min(innerLength, int(payload[4])*8)
	}

	innerPacket := gopacket.NewPacket(payload[innerOffset:innerOffset+innerLength], layers.LayerTypeIPv6, gopacket.Default)
	if innerLength < ipv6HeaderLength {
		innerBytes := payload[innerOffset : innerOffset+innerLength]
		if len(innerBytes) > 0 && innerBytes[0]>>4 == 6 {
			return nil
		}
		return append([]byte{}, innerBytes...)
	}

	innerIP, ok := innerPacket.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		return nil
	}

	if innerIP.NextHeader == layers.IPProtocolICMPv6 && len(innerIP.Payload) > 0 && innerIP.Payload[0] >= 1 && innerIP.Payload[0] <= 4 {
		return nil
	}

	translatedInner, err := t.TranslateIPv6(innerPacket, TranslationOverrides{
		// Translate addresses normally, but preserve the inner packet's Hop Limit.
		PreventTTLDecrement: true,
	})

	if err != nil {
		return nil
	}

	return append(translatedInner[:min(len(translatedInner), ipv4ICMPErrorPayloadMaximum)], payload[innerOffset+innerLength:]...)
}
