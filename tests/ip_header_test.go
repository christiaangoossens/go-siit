package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Section 4.1: ordinary IPv4 options are ignored; no IPv6 extension header or options are produced.
func TestTranslateIPv4OrdinaryOptions(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolTCP,
		SrcIP: ipv4Source, DstIP: ipv4Dest,
		Options: []layers.IPv4Option{
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
		},
	}
	tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, SYN: true, Window: testTCPWindow}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload([]byte("opt"))), layers.LayerTypeIPv4, gopacket.Default)
	if parsed := input.Layer(layers.LayerTypeIPv4).(*layers.IPv4); parsed.IHL <= 5 {
		t.Fatalf("test packet does not carry IPv4 options: IHL=%d", parsed.IHL)
	}
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || packet.ErrorLayer() != nil {
		t.Fatalf("ordinary IPv4 option prevented translation: %v", packet.ErrorLayer())
	}
	// Payload Length is the IPv4 Total Length minus the IPv4 header *and* options (RFC 7915 Section 4.1).
	if ip6.NextHeader != layers.IPProtocolTCP || int(ip6.Length) != 20+len("opt") || len(result) != ipv6HeaderLength+20+len("opt") {
		t.Fatalf("IPv4 options leaked into the IPv6 packet: next header %d, payload length %d, packet length %d", ip6.NextHeader, ip6.Length, len(result))
	}
	translatedTCP, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.Equal(translatedTCP.Payload, []byte("opt")) || translatedTCP.Checksum != recalculatedTCPChecksum(t, ip6, translatedTCP) {
		t.Fatalf("TCP segment was not translated after ignoring options: %v", packet.ErrorLayer())
	}
}

// RFC 7915 Section 4.1: an unexpired source-route option is discarded and returns ICMPv4 Source Route Failed.
// Local API contract: the generated ICMPv4 error is returned in Packet with a nil error.
func TestTranslateIPv4SourceRouteOptionReturnsICMPError(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolTCP,
		SrcIP: ipv4Source, DstIP: ipv4Dest,
		Options: []layers.IPv4Option{{OptionType: 137, OptionLength: 7, OptionData: []byte{4, 0, 0, 0, 0}}},
	}
	tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, SYN: true, Window: testTCPWindow}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, tcp), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	if err != nil {
		t.Fatalf("IPv4 source-route packet returned an error: %v", err)
	}
	packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default)
	outer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || !outer.SrcIP.Equal(ipv4RouterAddress) || !outer.DstIP.Equal(ipv4Source) || outer.Protocol != layers.IPProtocolICMPv4 {
		t.Fatalf("unexpected source-route error IPv4 header: %+v", outer)
	}
	icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 5) {
		t.Fatalf("unexpected source-route error ICMP: %+v", icmp)
	}
	if icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
		t.Fatalf("source-route error checksum is invalid: %#x", icmp.Checksum)
	}
	quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	if quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4); !ok || !quotedIP.SrcIP.Equal(ipv4Source) || !quotedIP.DstIP.Equal(ipv4Dest) || len(quotedIP.Options) == 0 {
		t.Fatalf("source-route error did not quote the original IPv4 header: %v", quoted.ErrorLayer())
	}
}

func ipv6PacketWithExtension(t *testing.T, extensionType layers.IPProtocol, routingSegmentsLeft uint8) gopacket.Packet {
	t.Helper()
	base := ipv6TCPPacket(t, defaultTTL).Data()
	const extensionLength = 8
	packetBytes := make([]byte, ipv6HeaderLength+extensionLength+len(base)-ipv6HeaderLength)
	copy(packetBytes, base[:ipv6HeaderLength])
	packetBytes[6] = byte(extensionType)
	binary.BigEndian.PutUint16(packetBytes[4:6], uint16(len(packetBytes)-ipv6HeaderLength))
	extension := packetBytes[ipv6HeaderLength : ipv6HeaderLength+extensionLength]
	extension[0] = byte(layers.IPProtocolTCP)
	extension[1] = 0
	if extensionType == layers.IPProtocolIPv6Routing {
		extension[3] = routingSegmentsLeft
	}
	copy(packetBytes[ipv6HeaderLength+extensionLength:], base[ipv6HeaderLength:])
	return gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.Default)
}

// RFC 7915 Section 5.1: zero-segment Destination Options and Routing headers may be traversed.
func TestTranslateIPv6ZeroSegmentExtensions(t *testing.T) {
	tests := []struct {
		name          string
		extensionType layers.IPProtocol
	}{
		{name: "destination options", extensionType: layers.IPProtocolIPv6Destination},
		{name: "routing with no segments", extensionType: layers.IPProtocolIPv6Routing},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv6PacketWithExtension(t, test.extensionType, 0)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			requireIPv6ExtensionSkipped(t, result)
		})
	}
}

// RFC 7915 Section 5.1: IPv6 Hop-by-Hop extension headers are ignored while translating to IPv4.
func TestTranslateIgnoresIPv6HopByHop(t *testing.T) {
	input := ipv6PacketWithExtension(t, layers.IPProtocolIPv6HopByHop, 0)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	requireIPv6ExtensionSkipped(t, result)
}

func requireIPv6ExtensionSkipped(t *testing.T, result []byte) {
	t.Helper()
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatalf("translated extension packet has no IPv4 layer: %v", packet.ErrorLayer())
	}
	if ip.Protocol != layers.IPProtocolTCP || ip.Length != uint16(len(result)) || ip.Checksum != ipv4HeaderChecksum(ip) {
		t.Fatalf("IPv6 extension was not removed from the IPv4 packet: %+v", ip)
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.Equal(tcp.Payload, []byte("hello")) {
		t.Fatalf("IPv6 extension translation changed the TCP payload: %v", packet.ErrorLayer())
	}
}

// RFC 7915 Section 5.1: Routing headers with remaining segments must not be forwarded and should generate a Parameter Problem for Segments Left.
func TestTranslateRejectsNonzeroSegmentRouting(t *testing.T) {
	input := ipv6PacketWithExtension(t, layers.IPProtocolIPv6Routing, 1)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if err == nil {
		t.Fatal("nonzero-segment IPv6 routing header was accepted")
	}
	if result.Packet == nil {
		t.Fatalf("routing header rejection did not return an ICMPv6 Parameter Problem: %v", err)
	}
	packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
	icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(4, 0) {
		t.Fatalf("routing header rejection returned the wrong ICMPv6 error: %v", packet.ErrorLayer())
	}
	if got := icmpPointerValue(t, icmp.Payload); got != ipv6HeaderLength+3 {
		t.Fatalf("routing header error points to byte %d, want Segments Left at byte %d", got, ipv6HeaderLength+3)
	}
}

// Local robustness: inconsistent IPv4 and IPv6 payload lengths must be rejected.
func TestTranslateRejectsInconsistentPayloadLengths(t *testing.T) {
	tests := []struct {
		name      string
		packet    []byte
		layer     gopacket.LayerType
		lengthAt  int
		translate func(*siit.Translator, gopacket.Packet) (siit.TranslatedPacket, error)
	}{
		{
			name: "IPv4 total length",
			packet: func() []byte {
				return ipv4TCPPacket(t, defaultTTL).Data()
			}(),
			layer: layers.LayerTypeIPv4, lengthAt: 2,
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name: "IPv6 payload length",
			packet: func() []byte {
				return ipv6TCPPacket(t, defaultTTL).Data()
			}(),
			layer: layers.LayerTypeIPv6, lengthAt: 4,
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packetBytes := append([]byte(nil), test.packet...)
			binary.BigEndian.PutUint16(packetBytes[test.lengthAt:test.lengthAt+2], 1)
			input := gopacket.NewPacket(packetBytes, test.layer, gopacket.Default)
			if _, err := test.translate(testTranslator(), input); err == nil {
				t.Fatal("inconsistent payload length was accepted")
			}
		})
	}
}

// Local unicast-only scope: illegal source and destination addresses are rejected in both directions.
func TestTranslateRejectsIllegalAddressMatrix(t *testing.T) {
	tests := []struct {
		name      string
		packet    gopacket.Packet
		translate func(*siit.Translator, gopacket.Packet) (siit.TranslatedPacket, error)
	}{
		{
			name:   "IPv4 unspecified source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.IPv4zero, ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 multicast source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("224.0.0.1"), ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 multicast destination",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, net.ParseIP("224.0.0.1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 broadcast destination",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, net.IPv4bcast),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 broadcast source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.IPv4bcast, ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 loopback source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("127.0.0.1"), ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 loopback destination",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, net.ParseIP("127.0.0.1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 loopback source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.IPv6loopback, ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 loopback destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.IPv6loopback),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 unspecified source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.IPv6zero, ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 multicast source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("ff02::1"), ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 unspecified destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.IPv6zero),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 multicast destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.ParseIP("ff02::1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 link-local source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("fe80::1"), ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 link-local destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.ParseIP("fe80::1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(testTranslator(), test.packet)
			if err == nil || result.Packet != nil {
				address := "unknown"
				if ip, ok := test.packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
					address = fmt.Sprintf("%s -> %s", ip.SrcIP, ip.DstIP)
				} else if ip, ok := test.packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
					address = fmt.Sprintf("%s -> %s", ip.SrcIP, ip.DstIP)
				}
				t.Fatalf("illegal address %s was not rejected: result length=%d err=%v", address, len(result.Packet), err)
			}
		})
	}
}

// RFC 7915 Sections 4.1 and 5.1: zero and one TTL/Hop Limit values generate complete Time Exceeded errors.
func TestTranslateExpiredTTLBoundaries(t *testing.T) {
	for _, ttl := range []uint8{0, 1} {
		t.Run("IPv4 TTL "+fmt.Sprint(ttl), func(t *testing.T) {
			result, err := testTranslator().TranslateIPv4(ipv4TCPPacket(t, ttl), siit.TranslationOverrides{})
			if !errors.Is(err, siit.ErrTimeExceeded) {
				t.Fatalf("got error %v, want ErrTimeExceeded", err)
			}
			translationErr, ok := err.(*siit.TranslationError)
			if !ok || !bytes.Equal(translationErr.Packet, result.Packet) {
				t.Fatalf("TranslationError.Packet does not match returned packet: %T", err)
			}
			packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || ip.NextHeader != layers.IPProtocolICMPv6 {
				t.Fatalf("missing generated IPv6 ICMP error: %v", packet.ErrorLayer())
			}
			icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(3, 0) || icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
				t.Fatalf("invalid generated IPv6 Time Exceeded: %v", packet.ErrorLayer())
			}
			quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv6, gopacket.Default)
			quotedIP, ok := quoted.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || quotedIP.HopLimit != ttl {
				t.Fatalf("generated quote has Hop Limit %d, want %d", quotedIP.HopLimit, ttl)
			}
		})

		t.Run("IPv6 Hop Limit "+fmt.Sprint(ttl), func(t *testing.T) {
			result, err := testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, ttl, ipv6Dest, ipv6Source), siit.TranslationOverrides{})
			if !errors.Is(err, siit.ErrTimeExceeded) {
				t.Fatalf("got error %v, want ErrTimeExceeded", err)
			}
			translationErr, ok := err.(*siit.TranslationError)
			if !ok || !bytes.Equal(translationErr.Packet, result.Packet) {
				t.Fatalf("TranslationError.Packet does not match returned packet: %T", err)
			}
			packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ip.Protocol != layers.IPProtocolICMPv4 || ip.Checksum != ipv4HeaderChecksum(ip) {
				t.Fatalf("invalid generated IPv4 ICMP error: %v", packet.ErrorLayer())
			}
			icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(11, 0) || icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
				t.Fatalf("invalid generated IPv4 Time Exceeded: %v", packet.ErrorLayer())
			}
			quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
			quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || quotedIP.TTL != ttl {
				t.Fatalf("generated quote has TTL %d, want %d", quotedIP.TTL, ttl)
			}
		})
	}
}

func ipv6PacketWithHopByHopAndRouting(t *testing.T, segmentsLeft uint8) gopacket.Packet {
	t.Helper()
	base := ipv6TCPPacket(t, defaultTTL).Data()
	hopByHop := []byte{byte(layers.IPProtocolIPv6Routing), 0, 1, 4, 0, 0, 0, 0}
	routing := []byte{byte(layers.IPProtocolTCP), 0, 0, segmentsLeft, 0, 0, 0, 0}
	payload := append(append(append([]byte{}, hopByHop...), routing...), base[ipv6HeaderLength:]...)
	packet := append([]byte{}, base[:ipv6HeaderLength]...)
	packet[6] = byte(layers.IPProtocolIPv6HopByHop)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	return gopacket.NewPacket(append(packet, payload...), layers.LayerTypeIPv6, gopacket.Default)
}

// RFC 7915 Section 5.1: the Parameter Problem pointer addresses the first byte of Segments Left, which is
// 40 + 8 (Hop-by-Hop) + 3 when the Routing header follows a Hop-by-Hop header.
func TestTranslateRoutingHeaderPointerAccountsForPrecedingExtensions(t *testing.T) {
	result, err := testTranslator().TranslateIPv6(ipv6PacketWithHopByHopAndRouting(t, 1), siit.TranslationOverrides{})
	if err == nil || result.Packet == nil {
		t.Fatalf("routing header with segments left was not rejected with an ICMPv6 error: err=%v", err)
	}
	icmp, ok := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0) {
		t.Fatalf("wrong ICMPv6 error for routing header: %+v", icmp)
	}
	if got := icmpPointerValue(t, icmp.Payload); got != ipv6HeaderLength+8+3 {
		t.Fatalf("pointer is %d, want %d", got, ipv6HeaderLength+8+3)
	}
}

// RFC 4443 Section 3.4: the Parameter Problem message includes as much of the invoking packet as fits.
func TestTranslateRoutingHeaderErrorQuotesInvokingPacket(t *testing.T) {
	input := ipv6PacketWithHopByHopAndRouting(t, 1)
	result, _ := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	const quoteOffset = ipv6HeaderLength + 4 + 4 // outer IPv6 header, ICMPv6 header, pointer
	if len(result.Packet) < quoteOffset+ipv6HeaderLength || !bytes.Equal(result.Packet[quoteOffset:quoteOffset+ipv6HeaderLength], input.Data()[:ipv6HeaderLength]) {
		t.Fatalf("Parameter Problem does not quote the invoking packet (length %d)", len(result.Packet))
	}
}

func ipv4TCPPacketWithOptions(t *testing.T, options ...layers.IPv4Option) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolTCP,
		SrcIP: ipv4Source, DstIP: ipv4Dest, Options: options,
	}
	tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, SYN: true, Window: testTCPWindow}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload([]byte("opt"))), layers.LayerTypeIPv4, gopacket.Default)
}

// RFC 7915 Section 4.1: only an *unexpired* source route is rejected; once the pointer has passed the end of
// the option, the option is ignored like any other and the packet is translated.
func TestTranslateIPv4ExpiredSourceRouteIsTranslated(t *testing.T) {
	for _, test := range []struct {
		name       string
		optionType uint8
	}{
		{name: "loose source route", optionType: 131},
		{name: "strict source route", optionType: 137},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Option length 7, pointer 8: the pointer is past the end of the option, so the route is used up.
			input := ipv4TCPPacketWithOptions(t,
				layers.IPv4Option{OptionType: test.optionType, OptionLength: 7, OptionData: []byte{8, 9, 9, 9, 9}},
				layers.IPv4Option{OptionType: 1, OptionLength: 1})
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			if _, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); !ok || packet.Layer(layers.LayerTypeTCP) == nil {
				t.Fatalf("expired source route packet was not translated to IPv6: %v", packet.ErrorLayer())
			}
		})
	}
}

// RFC 7915 Section 4.1: an unexpired loose source route is discarded with ICMPv4 Source Route Failed.
func TestTranslateIPv4UnexpiredLooseSourceRouteFails(t *testing.T) {
	input := ipv4TCPPacketWithOptions(t,
		layers.IPv4Option{OptionType: 131, OptionLength: 7, OptionData: []byte{4, 9, 9, 9, 9}},
		layers.IPv4Option{OptionType: 1, OptionLength: 1})
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	if err != nil || result.Packet == nil {
		t.Fatalf("source route error was not generated: err=%v", err)
	}
	icmp, ok := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 5) {
		t.Fatalf("wrong ICMPv4 error for an unexpired loose source route: %+v", icmp)
	}
}

// RFC 7915 Section 5.1: the IPv4 Identification of an unfragmented packet is "set according to a Fragment
// Identification generator at the translator", so successive packets do not all share one value.
func TestTranslateIPv6ToIPv4SetsIdentification(t *testing.T) {
	ids := map[uint16]bool{}
	for range 4 {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolGRE, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv6, gopacket.Default)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		})
		ids[binary.BigEndian.Uint16(result[4:6])] = true
	}
	if len(ids) < 2 {
		t.Fatalf("all translated packets carry the same IPv4 Identification: %v", ids)
	}
}

// RFC 7915 Section 5.1: Hop-by-Hop, Destination Options, and Routing (Segments Left 0) headers are skipped,
// including when several are chained.
func TestTranslateIPv6ExtensionHeaderChains(t *testing.T) {
	segment := ipv6TCPPacket(t, defaultTTL).Data()[ipv6HeaderLength:]
	padded := func(next layers.IPProtocol) []byte { return []byte{byte(next), 0, 1, 4, 0, 0, 0, 0} }
	routing := func(next layers.IPProtocol) []byte { return []byte{byte(next), 0, 0, 0, 0, 0, 0, 0} }
	tests := []struct {
		name  string
		first layers.IPProtocol
		chain []byte
	}{
		{
			name: "hop-by-hop then destination options", first: layers.IPProtocolIPv6HopByHop,
			chain: append(padded(layers.IPProtocolIPv6Destination), padded(layers.IPProtocolTCP)...),
		},
		{
			name: "routing then destination options", first: layers.IPProtocolIPv6Routing,
			chain: append(routing(layers.IPProtocolIPv6Destination), padded(layers.IPProtocolTCP)...),
		},
		{
			name: "hop-by-hop, routing and destination options", first: layers.IPProtocolIPv6HopByHop,
			chain: append(append(padded(layers.IPProtocolIPv6Routing), routing(layers.IPProtocolIPv6Destination)...), padded(layers.IPProtocolTCP)...),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: test.first, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(append(append([]byte{}, test.chain...), segment...))), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			requireIPv6ExtensionSkipped(t, result)
		})
	}
}
