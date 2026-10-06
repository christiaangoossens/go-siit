package siit_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.2 and 4.3, RFC 4884 Sections 3 and 4: IPv4 ICMP extensions survive IPv4-to-IPv6 translation with an updated length.
func TestTranslateIPv4ICMPErrorPreservesExtension(t *testing.T) {
	inner := ipv4TCPPacket(t, defaultTTL).Data()
	inner = append(inner, make([]byte, 128-len(inner))...)
	extension := icmpExtension()
	input := ipv4ICMPErrorWithExtension(t, layers.ICMPv4TypeDestinationUnreachable, 3, inner, extension)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	outer := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	icmp, ok := outer.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok {
		t.Fatalf("missing translated ICMPv6 layer: %v", outer.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv6Checksum(t, outer.Layer(layers.LayerTypeIPv6).(*layers.IPv6), icmp) {
		t.Fatalf("translated ICMPv6 extension checksum is invalid: %#x", icmp.Checksum)
	}
	requireICMPv6Extension(t, icmp, extension)
}

// RFC 7915 Sections 4.2, 5.2, and RFC 4884: opaque ICMP extension bytes are preserved and follow the translated quoted packet.
func TestTranslateICMPErrorPreservesOpaqueExtensionBytes(t *testing.T) {
	inner := ipv6TCPPacket(t, defaultTTL).Data()
	inner = append(inner, make([]byte, 128-len(inner))...)
	extension := icmpExtension()
	input := ipv6ICMPErrorWithExtension(t, layers.ICMPv6TypeDestinationUnreachable, 4, inner, extension)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if err != nil {
		t.Fatalf("valid ICMP error with an extension failed: %v", err)
	}
	outer := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default)
	icmp, ok := outer.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		t.Fatalf("missing translated ICMPv4 layer: %v", outer.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
		t.Fatalf("translated ICMPv4 extension checksum is invalid: %#x", icmp.Checksum)
	}
	requireICMPv4Extension(t, icmp, extension)
}

// RFC 4884 Sections 3, 4, and 7: extensions are valid on IPv6 Time Exceeded messages.
func TestTranslateIPv6ICMPErrorExtensionVariants(t *testing.T) {
	for _, test := range []struct {
		name        string
		messageType uint8
	}{
		{name: "time exceeded", messageType: layers.ICMPv6TypeTimeExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := ipv6TCPPacket(t, defaultTTL).Data()
			inner = append(inner, make([]byte, 128-len(inner))...)
			input := ipv6ICMPErrorWithExtension(t, test.messageType, 0, inner, icmpExtension())
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok {
				t.Fatalf("missing translated ICMPv4 layer: %v", packet.ErrorLayer())
			}
			requireICMPv4Extension(t, icmp, icmpExtension())
			if icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
				t.Fatalf("translated ICMPv6 %s extension checksum is invalid: %#x", test.name, icmp.Checksum)
			}
		})
	}
}

// RFC 4884 Sections 3, 4, and 7: extensions are valid on IPv4 Time Exceeded and Parameter Problem messages.
func TestTranslateIPv4ICMPErrorExtensionVariants(t *testing.T) {
	for _, test := range []struct {
		name        string
		messageType uint8
	}{
		{name: "time exceeded", messageType: layers.ICMPv4TypeTimeExceeded},
		{name: "parameter problem", messageType: layers.ICMPv4TypeParameterProblem},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := ipv4TCPPacket(t, defaultTTL).Data()
			inner = append(inner, make([]byte, 128-len(inner))...)
			input := ipv4ICMPErrorWithExtension(t, test.messageType, 0, inner, icmpExtension())
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok {
				t.Fatalf("missing translated ICMPv6 layer: %v", packet.ErrorLayer())
			}
			requireICMPv6Extension(t, icmp, icmpExtension())
			if icmp.Checksum != recalculatedICMPv6Checksum(t, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), icmp) {
				t.Fatalf("translated ICMPv4 %s extension checksum is invalid: %#x", test.name, icmp.Checksum)
			}
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
	return ipv6ICMPErrorPacket(t, ipv6Source, ipv6Dest, messageType, code, restHeader, append(append([]byte{}, originalDatagram...), extension...))
}

func ipv4ICMPErrorWithExtension(t *testing.T, messageType, code uint8, originalDatagram, extension []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
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

func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
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
