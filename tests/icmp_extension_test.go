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

// RFC 7915 Sections 4.2 and 5.2 (MUST) with RFC 4884 Sections 3, 4 and 7: an ICMP extension structure is carried
// over after the translated quote, and the Length attribute (octet 5 in 32-bit words for ICMPv4, octet 4 in 64-bit
// words for ICMPv6) is recomputed for the translated, zero-padded original datagram. The quoted packet grows by 20
// octets towards IPv6 and shrinks by 20 towards IPv4, so the length changes with the size of the quote in both
// directions. Extensions are only defined for Destination Unreachable and Time Exceeded.
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

// RFC 7915 Section 4.2 (SHOULD, left out when it cannot be truncated, see the README) with RFC 4884 Section 5:
// when the extension no longer fits next to a 128-octet quote in the 1280-octet ICMPv6 message, the message is
// sent with the translated quote only, and the Length attribute is zero.
func TestTranslateICMPExtensionThatDoesNotFitIsLeftOut(t *testing.T) {
	quote := ipv4TCPPayloadPacket(t, make([]byte, 128-ipv4HeaderLength-20), nil).Data()
	input := ipv4ICMPErrorWithExtension(t, layers.ICMPv4TypeDestinationUnreachable, 3, paddedDatagram(quote, 4), opaqueExtension(1300))
	result := translateToICMPv6(t, translatorWithMTU(t, 1500), input)
	if len(result.raw) > maxIPv6PacketLength || result.icmp.Payload[0] != 0 {
		t.Fatalf("message of %d octets with length attribute %d, want at most %d octets and no extension", len(result.raw), result.icmp.Payload[0], maxIPv6PacketLength)
	}
	requireQuotedTCPv6Prefix(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest)
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
