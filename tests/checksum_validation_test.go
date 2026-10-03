package siit_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.5 and 5.5: transport checksums must follow both checksum-neutral and non-neutral address mappings.
func TestTransportChecksumsFollowNeutralAndNonNeutralMappings(t *testing.T) {
	input := ipv4TCPPacket(t, defaultTTL)
	cases := []struct {
		name        string
		source      []byte
		destination []byte
	}{
		{
			name:        "checksum-neutral default mapping",
			source:      ipv4TranslatedSource,
			destination: ipv4TranslatedDest,
		},
		{
			name:        "non-neutral address override",
			source:      netIP("2001:db8::10"),
			destination: netIP("2001:db8::20"),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := mustTranslate(t, func() ([]byte, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{SourceIP: test.source, DestinationIP: test.destination})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) {
				t.Fatalf("checksum does not match mapped pseudo-header: %#x", tcp.Checksum)
			}
		})
	}
}

// RFC 7915 Sections 4.5 and 5.5: UDP checksums must cover the translated pseudo-header.
func TestUDPChecksumFollowsNonNeutralAddressMapping(t *testing.T) {
	input := ipv4UDPPacket(t, []byte("dns"))
	result := mustTranslate(t, func() ([]byte, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{
			SourceIP:      netIP("2001:db8::10"),
			DestinationIP: netIP("2001:db8::20"),
		})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		t.Fatalf("translated packet has no UDP layer: %v", packet.ErrorLayer())
	}
	if udp.Checksum != recalculatedUDPChecksum(t, ip, udp) {
		t.Fatalf("UDP checksum does not match the non-neutral pseudo-header: %#x", udp.Checksum)
	}
}

// RFC 7915 Sections 4.2 and 5.2: ICMP checksums must cover the translated ICMP pseudo-header.
func TestICMPChecksumFollowsNonNeutralAddressMapping(t *testing.T) {
	input := ipv4ICMPPacket(t, echoRequest, 0, []byte("icmp"))
	result := mustTranslate(t, func() ([]byte, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{
			SourceIP:      netIP("2001:db8::10"),
			DestinationIP: netIP("2001:db8::20"),
		})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok {
		t.Fatalf("translated packet has no ICMPv6 layer: %v", packet.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
		t.Fatalf("ICMP checksum does not match the non-neutral pseudo-header: %#x", icmp.Checksum)
	}
}

// RFC 7915 Sections 4.3 and 5.3: the quoted packet's TTL or Hop Limit is unchanged in either translation direction.
func TestTranslateIPv4ICMPErrorPreservesQuotedTTL(t *testing.T) {
	inner := ipv4TCPPacketWithAddresses(t, 37, ipv4Source, ipv4Dest)
	input := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, inner.Data())
	result := mustTranslate(t, func() ([]byte, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	outer := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	icmp, ok := outer.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok {
		t.Fatalf("missing translated ICMPv6 layer: %v", outer.ErrorLayer())
	}
	quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv6, gopacket.Default)
	ip, ok := quoted.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || ip.HopLimit != 37 || !ip.SrcIP.Equal(ipv4TranslatedSource) || !ip.DstIP.Equal(ipv4TranslatedDest) || ip.NextHeader != layers.IPProtocolTCP {
		t.Fatalf("quoted IPv4 TTL was decremented during translation: %+v", ip)
	}
	tcp, ok := quoted.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.Equal(tcp.Payload, []byte("hello")) {
		t.Fatalf("quoted IPv4 transport data was not translated: %v", quoted.ErrorLayer())
	}
	if outerIP := outer.Layer(layers.LayerTypeIPv6).(*layers.IPv6); outerIP.Length != uint16(len(result)-ipv6HeaderLength) {
		t.Fatalf("translated IPv4 ICMP error has incorrect IPv6 payload length: %d", outerIP.Length)
	}
}

// RFC 7915 Sections 4.2 and 4.3, RFC 4884 Sections 3 and 4: IPv4 ICMP extensions survive IPv4-to-IPv6 translation with an updated length.
func TestTranslateIPv4ICMPErrorPreservesExtension(t *testing.T) {
	inner := ipv4TCPPacket(t, defaultTTL).Data()
	inner = append(inner, make([]byte, 128-len(inner))...)
	extension := icmpExtension()
	input := ipv4ICMPErrorWithExtension(t, layers.ICMPv4TypeDestinationUnreachable, 3, inner, extension)
	result := mustTranslate(t, func() ([]byte, error) {
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
	if !bytes.HasSuffix(icmp.Payload, extension) {
		t.Fatal("ICMP extension was not preserved")
	}
	expectedOriginalLength := ipv6HeaderLength + len(inner) - ipv4HeaderLength
	if got := icmpv6ExtensionLength(icmp); got != uint8((expectedOriginalLength+7)/8) {
		t.Fatalf("translated ICMPv6 original-datagram length is %d words, want %d", got, (expectedOriginalLength+7)/8)
	}
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
	outer := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	icmp, ok := outer.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		t.Fatalf("missing translated ICMPv4 layer: %v", outer.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
		t.Fatalf("translated ICMPv4 extension checksum is invalid: %#x", icmp.Checksum)
	}
	if !bytes.HasSuffix(icmp.Payload, extension) {
		t.Fatal("opaque ICMP extension bytes were not preserved")
	}
	expectedOriginalLength := ipv4HeaderLength + len(inner) - ipv6HeaderLength
	if got := icmpv4ExtensionLength(icmp); got != uint8(expectedOriginalLength/4) {
		t.Fatalf("translated ICMPv4 original-datagram length is %d words, want %d", got, expectedOriginalLength/4)
	}
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
			result := mustTranslate(t, func() ([]byte, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || !bytes.HasSuffix(icmp.Payload, icmpExtension()) {
				t.Fatalf("translated ICMPv6 %s extension was not preserved: %v", test.name, packet.ErrorLayer())
			}
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
			result := mustTranslate(t, func() ([]byte, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok || !bytes.HasSuffix(icmp.Payload, icmpExtension()) {
				t.Fatalf("translated ICMPv4 %s extension was not preserved: %v", test.name, packet.ErrorLayer())
			}
			if icmp.Checksum != recalculatedICMPv6Checksum(t, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), icmp) {
				t.Fatalf("translated ICMPv4 %s extension checksum is invalid: %#x", test.name, icmp.Checksum)
			}
		})
	}
}

func ipv6ICMPErrorWithExtension(t *testing.T, messageType, code uint8, originalDatagram, extension []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(messageType, code)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	if len(originalDatagram)%8 != 0 || len(originalDatagram) < 128 {
		t.Fatalf("ICMPv6 extension original datagram must be at least 128 bytes and 64-bit aligned: %d", len(originalDatagram))
	}
	restHeader := make([]byte, icmpErrorRestHeaderSize)
	restHeader[0] = byte(len(originalDatagram) / 8)
	payload := append(restHeader, originalDatagram...)
	payload = append(payload, extension...)
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
}

func ipv4ICMPErrorWithExtension(t *testing.T, messageType, code uint8, originalDatagram, extension []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	if len(originalDatagram)%4 != 0 || len(originalDatagram) < 128 {
		t.Fatalf("ICMPv4 extension original datagram must be at least 128 bytes and 32-bit aligned: %d", len(originalDatagram))
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(messageType, code),
		Id:       uint16(len(originalDatagram) / 4 << 8),
	}
	payload := append(originalDatagram, extension...)
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

func icmpv4ExtensionLength(icmp *layers.ICMPv4) uint8 {
	return icmp.Contents[5]
}

func icmpv6ExtensionLength(icmp *layers.ICMPv6) uint8 {
	if len(icmp.Payload) == 0 {
		return 0
	}
	return icmp.Payload[0]
}

// RFC 7915 Sections 4.3 and 5.3: translating an ICMP error must not decrement the quoted packet's TTL or Hop Limit.
func TestTranslateICMPErrorPreservesQuotedHopLimit(t *testing.T) {
	inner := ipv6TCPPacketWithAddresses(t, 37, ipv6Source, ipv6Dest)
	input := ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, inner.Data())
	result := mustTranslate(t, func() ([]byte, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	outer := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	icmp, ok := outer.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		t.Fatalf("missing translated ICMPv4 layer: %v", outer.ErrorLayer())
	}
	quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || ip.TTL != 37 || !ip.SrcIP.Equal(ipv4RouterAddress) || !ip.DstIP.Equal(ipv6TranslatedDest) || ip.Protocol != layers.IPProtocolTCP {
		t.Fatalf("quoted IPv6 Hop Limit was decremented during translation: %+v", ip)
	}
	tcp, ok := quoted.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.Equal(tcp.Payload, []byte("hello")) {
		t.Fatalf("quoted IPv6 transport data was not translated: %v", quoted.ErrorLayer())
	}
	if outerIP := outer.Layer(layers.LayerTypeIPv4).(*layers.IPv4); outerIP.Length != uint16(len(result)) {
		t.Fatalf("translated IPv6 ICMP error has incorrect IPv4 total length: %d", outerIP.Length)
	}
}

// RFC 7915 Sections 4.3 and 5.3: an ICMP error containing a nested IP packet must be dropped.
func TestTranslateDropsNestedICMPError(t *testing.T) {
	inner := ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, ipv6TCPPacket(t, defaultTTL).Data())
	outer := ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, inner.Data())
	result, err := testTranslator().TranslateIPv6(outer, siit.TranslationOverrides{})
	if result != nil {
		t.Fatalf("nested IPv6 ICMP error was translated: err=%v", err)
	}
}

// RFC 7915 Section 4.3: an IPv4 ICMP error containing a nested IP packet must be dropped.
func TestTranslateDropsNestedIPv4ICMPError(t *testing.T) {
	inner := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, ipv4TCPPacket(t, defaultTTL).Data())
	outer := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, inner.Data())
	result, err := testTranslator().TranslateIPv4(outer, siit.TranslationOverrides{})
	if result != nil {
		t.Fatalf("nested IPv4 ICMP error was translated: err=%v", err)
	}
}

// RFC 7915 Sections 4.3 and 5.3: an ICMP error with an invalid quoted IP packet cannot be translated.
func TestTranslateDropsMalformedQuotedIPPacket(t *testing.T) {
	tests := []struct {
		name      string
		translate func(gopacket.Packet) ([]byte, error)
		input     gopacket.Packet
	}{
		{
			name:  "IPv4 outer and quote",
			input: ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, []byte{0x45, 0, 0, 20}),
			translate: func(input gopacket.Packet) ([]byte, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			},
		},
		{
			name:  "IPv6 outer and quote",
			input: ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, []byte{0x60, 0, 0, 0}),
			translate: func(input gopacket.Packet) ([]byte, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(test.input)
			if result != nil {
				t.Fatalf("malformed quoted packet was translated: err=%v", err)
			}
		})
	}
}

func netIP(address string) net.IP {
	return net.ParseIP(address)
}
