package siit_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Local API contract: the translator requires a /96 NAT64 prefix and an IPv4 router address.
func TestNewTranslatorValidatesConfiguration(t *testing.T) {
	_, validPrefix, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}
	_, shortPrefix, err := net.ParseCIDR("64:ff9b::/64")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		prefix     *net.IPNet
		routerAddr net.IP
	}{
		{name: "nil prefix", prefix: nil, routerAddr: ipv4RouterAddress},
		{name: "non /96 prefix", prefix: shortPrefix, routerAddr: ipv4RouterAddress},
		{name: "nil router", prefix: validPrefix, routerAddr: nil},
		{name: "IPv6 router", prefix: validPrefix, routerAddr: net.ParseIP("2001:db8::1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := siit.NewTranslator(test.prefix, test.routerAddr); err == nil {
				t.Fatal("invalid translator configuration was accepted")
			}
		})
	}
}

// RFC 7915 Section 4.1: ordinary IPv4 options are ignored while translating the packet.
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
	input := gopacket.NewPacket(serializeTestPacket(t, ip, tcp), layers.LayerTypeIPv4, gopacket.Default)
	result := mustTranslate(t, func() ([]byte, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	if packet.ErrorLayer() != nil {
		t.Fatalf("ordinary IPv4 option prevented translation: %v", packet.ErrorLayer())
	}
}

// RFC 7915 Section 4.1: an unexpired source-route option must cause the packet to be discarded.
func TestTranslateRejectsIPv4SourceRouteOption(t *testing.T) {
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
	if result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{}); err != nil || result != nil {
		t.Fatalf("IPv4 source-route packet %s -> %s was not silently dropped: result length=%d err=%v", ip.SrcIP, ip.DstIP, len(result), err)
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
			result := mustTranslate(t, func() ([]byte, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			requireIPv6ExtensionSkipped(t, result)
		})
	}
}

// RFC 7915 Section 5.1: IPv6 Hop-by-Hop extension headers are ignored while translating to IPv4.
func TestTranslateIgnoresIPv6HopByHop(t *testing.T) {
	input := ipv6PacketWithExtension(t, layers.IPProtocolIPv6HopByHop, 0)
	result := mustTranslate(t, func() ([]byte, error) {
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
	if result == nil {
		t.Fatalf("routing header rejection did not return an ICMPv6 Parameter Problem: %v", err)
	}
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
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
		translate func(*siit.Translator, gopacket.Packet) ([]byte, error)
	}{
		{
			name: "IPv4 total length",
			packet: func() []byte {
				return ipv4TCPPacket(t, defaultTTL).Data()
			}(),
			layer: layers.LayerTypeIPv4, lengthAt: 2,
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name: "IPv6 payload length",
			packet: func() []byte {
				return ipv6TCPPacket(t, defaultTTL).Data()
			}(),
			layer: layers.LayerTypeIPv6, lengthAt: 4,
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
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
		translate func(*siit.Translator, gopacket.Packet) ([]byte, error)
	}{
		{
			name:   "IPv4 unspecified source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.IPv4zero, ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 multicast source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("224.0.0.1"), ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 multicast destination",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, net.ParseIP("224.0.0.1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 broadcast destination",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, net.IPv4bcast),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv4 broadcast source",
			packet: ipv4TCPPacketWithAddresses(t, defaultTTL, net.IPv4bcast, ipv4Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 unspecified source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.IPv6zero, ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 multicast source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("ff02::1"), ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 unspecified destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.IPv6zero),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 multicast destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.ParseIP("ff02::1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 link-local source",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("fe80::1"), ipv6Dest),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:   "IPv6 link-local destination",
			packet: ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, net.ParseIP("fe80::1")),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(testTranslator(), test.packet)
			if err == nil || result != nil {
				address := "unknown"
				if ip, ok := test.packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
					address = fmt.Sprintf("%s -> %s", ip.SrcIP, ip.DstIP)
				} else if ip, ok := test.packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
					address = fmt.Sprintf("%s -> %s", ip.SrcIP, ip.DstIP)
				}
				t.Fatalf("illegal address %s was not rejected: result length=%d err=%v", address, len(result), err)
			}
		})
	}
}
