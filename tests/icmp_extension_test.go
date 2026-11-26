package siit_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// paddedDatagram zero-pads the quoted packet to the "original datagram" field of RFC 4884 Section 4: at least
// 128 octets and a whole number of words of the given size.
// icmpv6TypeFor maps the ICMPv4 error types under test to their ICMPv6 counterparts (RFC 7915 Section 4.2).
var icmpv6TypeFor = map[uint8]uint8{
	3:  layers.ICMPv6TypeDestinationUnreachable,
	11: layers.ICMPv6TypeTimeExceeded,
}

func paddedDatagram(quote []byte, word int) []byte {
	size := max(128, (len(quote)+word-1)/word*word)
	return append(append(make([]byte, 0, size), quote...), make([]byte, size-len(quote))...)
}

// opaqueExtension returns an extension structure (RFC 4884 Section 7) of the given size with a valid checksum
// and an object whose content is meaningless to the translator.
func opaqueExtension(size int) []byte {
	extension := make([]byte, size)
	extension[0] = 0x20
	binary.BigEndian.PutUint16(extension[4:6], uint16(size-4))
	extension[6], extension[7] = 1, 1
	binary.BigEndian.PutUint16(extension[2:4], checksum(extension))
	return extension
}

// RFC 7915 Section 4.2 (MUST): "the ICMPv6 Extension length attribute MUST be adjusted accordingly (e.g., longer due
// to the translation from IPv4 to IPv6)."
//
// RFC 7915 Section 5.2 (MUST): "the ICMPv6 Extension length attribute MUST be adjusted accordingly (e.g., shorter due
// to the translation from IPv6 to IPv4)."
//
// The Length attribute (RFC 4884) counts 32-bit words for ICMPv4 and 64-bit words for ICMPv6.
func TestTranslateICMPExtensions(t *testing.T) {
	extension := icmpExtension()
	for _, size := range []int{60, 100, 124, 128, 148, 200} {
		for _, messageType := range []uint8{3, 11} {
			t.Run(fmt.Sprintf("IPv4 to IPv6/type %d/quote %d octets", messageType, size), func(t *testing.T) {
				quote := ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, size-ipv4HeaderLength-20), nil).Data()
				input := ipv4ICMPErrorWithExtension(t, messageType, 0, paddedDatagram(quote, 4), extension)
				result := translateToICMPv6(t, testTranslator(), input)
				requireICMPv6Extension(t, result.icmp, extension)
				want := max(128, (size+ipv6HeaderLength-ipv4HeaderLength+7)/8*8) / 8
				if got := int(result.icmp.Payload[0]); got != want {
					t.Fatalf("ICMPv6 length is %d words, want %d", got, want)
				}
				requireQuotedTCPv6Prefix(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest)
			})
			t.Run(fmt.Sprintf("IPv6 to IPv4/type %d/quote %d octets", messageType, size), func(t *testing.T) {
				quote := ipv6TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, size-ipv6HeaderLength-20)).Data()
				input := ipv6ICMPErrorWithExtension(t, icmpv6TypeFor[messageType], 0, paddedDatagram(quote, 8), extension)
				result := translateToICMPv4(t, testTranslator(), input)
				requireICMPv4Extension(t, result.icmp, extension)
				want := max(128, (size-(ipv6HeaderLength-ipv4HeaderLength)+3)/4*4) / 4
				if got := int(result.icmp.Contents[5]); got != want {
					t.Fatalf("ICMPv4 length is %d words, want %d", got, want)
				}
			})
		}
	}
}

func requireQuotedTCPv6Prefix(t *testing.T, quote gopacket.Packet, source, destination []byte) {
	t.Helper()
	ip, ok := quote.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || !bytes.Equal(ip.SrcIP, source) || !bytes.Equal(ip.DstIP, destination) || ip.NextHeader != layers.IPProtocolTCP {
		t.Fatalf("quoted IPv6 header is %+v", ip)
	}
}

// RFC 7915 Section 4.2 (SHOULD): "If the ICMPv4 Extension exceeds the maximum size of an ICMPv6 message on the
// outgoing interface, the ICMPv4 extension SHOULD be simply truncated."
//
// The library leaves it out instead (see the README), with a Length attribute of zero.
func TestTranslateICMPExtensionThatDoesNotFitIsLeftOut(t *testing.T) {
	quote := ipv4TCPPayloadPacket(t, make([]byte, 128-ipv4HeaderLength-20), nil).Data()
	input := ipv4ICMPErrorWithExtension(t, layers.ICMPv4TypeDestinationUnreachable, 3, paddedDatagram(quote, 4), opaqueExtension(1300))
	result := translateToICMPv6(t, translatorWithMTU(t, 1500), input)
	if len(result.raw) > maxIPv6PacketLength || result.icmp.Payload[0] != 0 {
		t.Fatalf("message of %d octets with length attribute %d, want at most %d octets and no extension", len(result.raw), result.icmp.Payload[0], maxIPv6PacketLength)
	}
	requireQuotedTCPv6Prefix(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest)
}

// extensionLimitCase is an ICMP error of which the quote and extension sizes in octets are given, with the expected
// length attribute (0 for no extension) and size of the translated packet.
type extensionLimitCase struct {
	name                 string
	quote, extension     int
	wantLength, wantSize int
}

// An ICMPv4 error stays within 576 octets (RFC 1812, as summarised in RFC 4884 Section 4). The quote is shortened
// first and the extension is kept whole. When not even a 128-octet quote fits next to it, the extension is left out
// and the length attribute is 0 (see docs/rfc-deviations.md).
//
// The rows follow Jool ic1-ic6, with TCP instead of UDP.
func TestTranslateICMPExtensionsAtTheICMPv4SizeLimit(t *testing.T) {
	tests := []extensionLimitCase{
		{"quote fits exactly", 528, 40, 127, 576},
		{"quote barely truncated", 536, 40, 127, 576},
		{"quote truncated", 1192, 40, 127, 576},
		{"extension fits exactly", 128, 420, 32, 576},
		{"extension too large", 128, 424, 0, 136},
		{"quote truncated and extension too large", 576, 524, 0, 576},
	}

	for _, test := range tests {
		for _, messageType := range []uint8{3, 11} {
			t.Run(fmt.Sprintf("%s/type %d", test.name, messageType), func(t *testing.T) {
				quote := ipv6TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, test.quote-ipv6HeaderLength-20)).Data()
				extension := opaqueExtension(test.extension)
				input := ipv6ICMPErrorWithExtension(t, icmpv6TypeFor[messageType], 0, paddedDatagram(quote, 8), extension)
				result := translateToICMPv4(t, testTranslator(), input)
				if len(result.raw) != test.wantSize || int(result.icmp.Contents[5]) != test.wantLength {
					t.Fatalf("message of %d octets with length attribute %d, want %d octets and %d", len(result.raw), result.icmp.Contents[5], test.wantSize, test.wantLength)
				}

				datagram := splitTranslatedExtension(t, result.icmp.Payload, test.wantLength*4, extension)
				requireFilledDatagram(t, datagram, ipv4HeaderLength+20, test.quote-ipv6HeaderLength+ipv4HeaderLength)
			})
		}
	}
}

// An ICMPv6 error stays within 1280 octets (RFC 4443, as summarised in RFC 4884 Section 4). The ICMPv4 length
// attribute holds at most 1020 octets of quote, so the input needs an IPv4 MTU above 1280.
//
// The rows follow Jool idb-idh and idz, with TCP instead of UDP. The 128-octet row is Jool idg with a shorter quote, to
// keep the input within the MTU of 1500.
func TestTranslateICMPExtensionsAtTheICMPv6SizeLimit(t *testing.T) {
	tests := []extensionLimitCase{
		{"quote and extension fit exactly", 572, 640, 74, 1280},
		{"long quote fits exactly", 1020, 192, 130, 1280},
		{"long extension fits exactly", 132, 1080, 19, 1280},
		{"quote truncated", 580, 640, 74, 1280},
		{"quote barely truncated", 576, 640, 74, 1280},
		{"long quote truncated", 1020, 200, 129, 1280},
		{"quote truncated to 128 octets", 348, 1104, 16, 1280},
		{"extension too large", 128, 1112, 0, 196},
	}

	for _, test := range tests {
		for _, messageType := range []uint8{3, 11} {
			t.Run(fmt.Sprintf("%s/type %d", test.name, messageType), func(t *testing.T) {
				quote := ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, test.quote-ipv4HeaderLength-20), nil).Data()
				extension := opaqueExtension(test.extension)
				input := ipv4ICMPErrorWithExtension(t, messageType, 0, paddedDatagram(quote, 4), extension)
				result := translateToICMPv6(t, translatorWithMTU(t, 1500), input)
				if len(result.raw) != test.wantSize || int(result.icmp.Payload[0]) != test.wantLength {
					t.Fatalf("message of %d octets with length attribute %d, want %d octets and %d", len(result.raw), result.icmp.Payload[0], test.wantSize, test.wantLength)
				}

				datagram := splitTranslatedExtension(t, result.icmp.Payload[icmpErrorRestHeaderSize:], test.wantLength*8, extension)
				requireFilledDatagram(t, datagram, ipv6HeaderLength+20, test.quote-ipv4HeaderLength+ipv6HeaderLength)
				requireQuotedTCPv6Prefix(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest)
			})
		}
	}
}

// RFC 4884 Section 4 requires an original datagram of at least 128 octets when an extension is appended, so a
// smaller length attribute is invalid. The translator then treats the whole rest of the message as the quote: the
// quoted packet ends at its own length, the extension is lost and the outgoing length attribute is 0.
//
// This pins the current behaviour. Jool (ic7, idk) instead pads the quote to 128 octets and keeps the extension.
func TestTranslateICMPExtensionWithLengthBelow128Octets(t *testing.T) {
	extension := opaqueExtension(40)

	t.Run("IPv6 to IPv4", func(t *testing.T) {
		quote := ipv6TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 4)).Data()
		restHeader := []byte{byte(len(quote) / 8), 0, 0, 0}
		input := ipv6ICMPErrorPacket(t, ipv6Dest, ipv6Source, icmpv6DestUnreachable, 4, restHeader, append(quote, extension...))
		result := translateToICMPv4(t, testTranslator(), input)
		want := len(quote) - ipv6HeaderLength + ipv4HeaderLength
		if result.icmp.Contents[5] != 0 || len(result.icmp.Payload) != want {
			t.Fatalf("length attribute %d with %d octets of data, want 0 and %d", result.icmp.Contents[5], len(result.icmp.Payload), want)
		}
	})

	t.Run("IPv4 to IPv6", func(t *testing.T) {
		quote := ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 4), nil).Data()
		input := ipv4ICMPPacketWithRest(t, 3, 3, uint16(len(quote)/4), 0, append(quote, extension...))
		result := translateToICMPv6(t, testTranslator(), input)
		want := icmpErrorRestHeaderSize + len(quote) - ipv4HeaderLength + ipv6HeaderLength
		if result.icmp.Payload[0] != 0 || len(result.icmp.Payload) != want {
			t.Fatalf("length attribute %d with %d octets of data, want 0 and %d", result.icmp.Payload[0], len(result.icmp.Payload), want)
		}

		requireQuotedTCPv6Prefix(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest)
	})
}

// splitTranslatedExtension returns the original datagram field of the given length in octets and checks that the
// extension follows it unchanged. A length of 0 means there is no extension: all data is the original datagram.
func splitTranslatedExtension(t *testing.T, data []byte, field int, extension []byte) []byte {
	t.Helper()
	if field == 0 {
		return data
	}

	if field > len(data) || !bytes.Equal(data[field:], extension) {
		t.Fatalf("extension does not follow the original datagram of %d octets in %d octets of data", field, len(data))
	}

	return data[:field]
}

// requireFilledDatagram checks an original datagram field that quotes a segment filled with 0x5a: the headers, then
// the fill up to the length of the translated quote or of the field, then zero padding.
func requireFilledDatagram(t *testing.T, datagram []byte, headers, translated int) {
	t.Helper()
	copied := min(len(datagram), translated)
	if copied < headers || !bytes.Equal(datagram[headers:copied], bytes.Repeat([]byte{0x5a}, copied-headers)) {
		t.Fatalf("original datagram of %d octets does not hold the translated quote of %d octets", len(datagram), translated)
	}

	requireZeroBytes(t, datagram[copied:], "original datagram")
}

// RFC 4884 Section 4 defines extensions for ICMPv4 Parameter Problem (octet 4 is the pointer, octet 5 the length),
// but an ICMPv6 Parameter Problem has no room for a length: its pointer occupies the whole four-byte word. The
// translated message therefore carries the translated quote only, without the extension structure.
func TestTranslateIPv4ParameterProblemExtensionIsNotCarriedToICMPv6(t *testing.T) {
	inner := paddedDatagram(ipv4TCPPacket(t, defaultTTL).Data(), 4)
	input := ipv4ICMPErrorWithExtension(t, layers.ICMPv4TypeParameterProblem, 0, inner, icmpExtension())
	result := translateToICMPv6(t, testTranslator(), input)
	if result.icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0) {
		t.Fatalf("missing translated ICMPv6 Parameter Problem: %v", result.icmp.TypeCode)
	}
	if got := icmpPointerValue(t, result.icmp.Payload); got != 0 {
		t.Fatalf("pointer is %d, want 0: the RFC 4884 length leaked into the pointer", got)
	}
	quote := result.quote(t)
	quotedIP, ok := quote.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || len(result.icmp.Payload) != icmpErrorRestHeaderSize+ipv6HeaderLength+int(quotedIP.Length) {
		t.Fatalf("Parameter Problem carries more than the translated quote (%d octets)", len(result.icmp.Payload))
	}
}

// RFC 4884 Section 4.6 (MUST NOT): "The ICMP Extension Structure MUST NOT be appended to any of the other ICMP
// messages mentioned in Section 4."
//
// ICMPv6 Packet Too Big and Parameter Problem have no length attribute, so the extension of an ICMPv4 3/4, 3/2 or
// 12/0 cannot be carried. The quote is 128 octets of a longer packet: only the ICMPv4 length attribute tells where
// the extension starts, and the ICMPv6 quote must stop there.
func TestTranslateICMPv4ExtensionIsLeftOutOfPacketTooBigAndParameterProblem(t *testing.T) {
	quote := ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 300), nil).Data()[:128]
	tests := []struct {
		messageType, code, wantType, wantCode uint8
	}{
		{3, 4, 2, 0},
		{3, 2, 4, 1},
		{12, 0, 4, 0},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%d/%d to %d/%d", test.messageType, test.code, test.wantType, test.wantCode), func(t *testing.T) {
			input := ipv4ICMPErrorWithExtension(t, test.messageType, test.code, quote, opaqueExtension(16))
			result := translateToICMPv6(t, testTranslator(), input)
			if result.icmp.TypeCode != layers.CreateICMPv6TypeCode(test.wantType, test.wantCode) {
				t.Fatalf("ICMPv6 type/code is %v, want %d/%d", result.icmp.TypeCode, test.wantType, test.wantCode)
			}

			want := icmpErrorRestHeaderSize + len(quote) + ipv6HeaderLength - ipv4HeaderLength
			if len(result.icmp.Payload) != want {
				t.Fatalf("ICMPv6 error carries %d octets after the ICMPv6 header, want %d: the extension leaked into the quote", len(result.icmp.Payload), want)
			}

			requireQuotedTCPv6Prefix(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest)
		})
	}
}

func ipv6ICMPErrorWithExtension(t *testing.T, messageType, code uint8, originalDatagram, extension []byte) gopacket.Packet {
	t.Helper()
	if len(originalDatagram)%8 != 0 || len(originalDatagram) < 128 {
		t.Fatalf("ICMPv6 extension original datagram must be at least 128 bytes and 64-bit aligned: %d", len(originalDatagram))
	}
	// RFC 4884 Section 4.4/4.5: octet 4 is the length of the padded original datagram in 64-bit words.
	restHeader := make([]byte, icmpErrorRestHeaderSize)
	restHeader[0] = byte(len(originalDatagram) / 8)
	return ipv6ICMPErrorPacket(t, ipv6Dest, ipv6Source, messageType, code, restHeader, append(append([]byte{}, originalDatagram...), extension...))
}

func ipv4ICMPErrorWithExtension(t *testing.T, messageType, code uint8, originalDatagram, extension []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Dest, DstIP: ipv4Source}
	if len(originalDatagram)%4 != 0 || len(originalDatagram) < 128 {
		t.Fatalf("ICMPv4 extension original datagram must be at least 128 bytes and 32-bit aligned: %d", len(originalDatagram))
	}
	// RFC 4884 Sections 4.1-4.3: octet 4 is unused (the pointer for Parameter Problem) and octet 5 is the
	// length of the padded original datagram in 32-bit words.
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(messageType, code),
		Id:       uint16(len(originalDatagram) / 4),
	}
	payload := append(append([]byte{}, originalDatagram...), extension...)
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

func icmpExtension() []byte {
	extension := []byte{0x20, 0, 0, 0, 0, 4, 0, 0}
	binary.BigEndian.PutUint16(extension[2:4], checksum(extension))
	return extension
}

func requireZeroBytes(t *testing.T, data []byte, what string) {
	t.Helper()
	for index, value := range data {
		if value != 0 {
			t.Fatalf("%s is not zero padded: byte %d is %#x", what, index, value)
		}
	}
}

// requireICMPv6Extension checks RFC 4884 Sections 3 and 4.4: the length (octet 4, in 64-bit words) covers the
// zero-padded original datagram of at least 128 octets, and the extension structure follows it directly.
func requireICMPv6Extension(t *testing.T, icmp *layers.ICMPv6, extension []byte) {
	t.Helper()
	if len(icmp.Payload) < icmpErrorRestHeaderSize {
		t.Fatalf("ICMPv6 error is too short: %d", len(icmp.Payload))
	}
	field := int(icmp.Payload[0]) * 8
	if field < 128 || icmpErrorRestHeaderSize+field > len(icmp.Payload) {
		t.Fatalf("ICMPv6 original datagram length %d octets is below 128 or exceeds the message (%d)", field, len(icmp.Payload))
	}
	datagram := icmp.Payload[icmpErrorRestHeaderSize : icmpErrorRestHeaderSize+field]
	quoted, ok := gopacket.NewPacket(datagram, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || ipv6HeaderLength+int(quoted.Length) > field {
		t.Fatalf("quoted IPv6 packet is invalid or longer than the declared original datagram length %d", field)
	}
	requireZeroBytes(t, datagram[ipv6HeaderLength+int(quoted.Length):], "ICMPv6 original datagram")
	if got := icmp.Payload[icmpErrorRestHeaderSize+field:]; !bytes.Equal(got, extension) {
		t.Fatalf("extension does not follow the original datagram: got %x, want %x", got, extension)
	}
}

// requireICMPv4Extension checks RFC 4884 Sections 3 and 4.1-4.3: the length (octet 5, in 32-bit words) covers the
// zero-padded original datagram of at least 128 octets, and the extension structure follows it directly.
func requireICMPv4Extension(t *testing.T, icmp *layers.ICMPv4, extension []byte) {
	t.Helper()
	field := int(icmp.Contents[5]) * 4
	if field < 128 || field > len(icmp.Payload) {
		t.Fatalf("ICMPv4 original datagram length %d octets is below 128 or exceeds the message (%d)", field, len(icmp.Payload))
	}
	datagram := icmp.Payload[:field]
	quoted, ok := gopacket.NewPacket(datagram, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || int(quoted.Length) > field {
		t.Fatalf("quoted IPv4 packet is invalid or longer than the declared original datagram length %d", field)
	}
	requireZeroBytes(t, datagram[quoted.Length:], "ICMPv4 original datagram")
	if got := icmp.Payload[field:]; !bytes.Equal(got, extension) {
		t.Fatalf("extension does not follow the original datagram: got %x, want %x", got, extension)
	}
}
