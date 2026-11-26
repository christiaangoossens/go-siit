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

// sourceRoute builds an IPv4 loose (131) or strict (137) source route option of length 7 with the given pointer.
func sourceRoute(optionType, pointer uint8) layers.IPv4Option {
	return layers.IPv4Option{OptionType: optionType, OptionLength: 7, OptionData: []byte{pointer, 9, 9, 9, 9}}
}

var (
	ipv4NOP         = layers.IPv4Option{OptionType: 1, OptionLength: 1}
	ipv4RecordRoute = layers.IPv4Option{OptionType: 7, OptionLength: 7, OptionData: []byte{4, 0, 0, 0, 0}}
	ipv4Timestamp   = layers.IPv4Option{OptionType: 68, OptionLength: 8, OptionData: []byte{5, 0, 0, 0, 0, 0}}
)

// RFC 7915 Section 4.1 (MUST): "If any IPv4 options are present in the IPv4 packet, they MUST be ignored and the
// packet translated normally; there is no attempt to translate the options. However, if an unexpired source route
// option is present, then the packet MUST instead be discarded, and an ICMPv4 'Destination Unreachable, Source Route
// Failed' (Type 3, Code 5) error message SHOULD be returned to the sender."
//
// A route is used up once its pointer lies beyond the option (RFC 791 Section 3.1).
func TestTranslateIPv4Options(t *testing.T) {
	tests := []struct {
		name         string
		options      []layers.IPv4Option
		sourceFailed bool
	}{
		{name: "no-operation", options: []layers.IPv4Option{ipv4NOP, ipv4NOP}},
		{name: "record route", options: []layers.IPv4Option{ipv4RecordRoute, ipv4NOP}},
		{name: "timestamp", options: []layers.IPv4Option{ipv4Timestamp, ipv4NOP, ipv4NOP}},
		{name: "expired loose source route", options: []layers.IPv4Option{sourceRoute(131, 8), ipv4NOP}},
		{name: "expired strict source route", options: []layers.IPv4Option{sourceRoute(137, 8), ipv4NOP}},
		{name: "unexpired loose source route", options: []layers.IPv4Option{sourceRoute(131, 4), ipv4NOP}, sourceFailed: true},
		{name: "unexpired strict source route", options: []layers.IPv4Option{sourceRoute(137, 4), ipv4NOP}, sourceFailed: true},
		{name: "unexpired source route after other options", options: []layers.IPv4Option{ipv4NOP, sourceRoute(131, 4)}, sourceFailed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv4TCPPacketWithOptions(t, test.options...)
			if parsed := input.Layer(layers.LayerTypeIPv4).(*layers.IPv4); parsed.IHL <= 5 {
				t.Fatalf("test packet does not carry IPv4 options: IHL=%d", parsed.IHL)
			}
			result, err := translateIPv4(t, testTranslator(), input)
			if test.sourceFailed {
				if !errors.Is(err, siit.ErrSourceRouteFailed) || result.packet != nil {
					t.Fatalf("got err=%v, packet length %d, want ErrSourceRouteFailed", err, len(result.packet))
				}
				packet := gopacket.NewPacket(result.reply, layers.LayerTypeIPv4, gopacket.Default)
				outer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if !ok || !outer.SrcIP.Equal(ipv4RouterAddress) || !outer.DstIP.Equal(ipv4Source) || outer.Protocol != layers.IPProtocolICMPv4 {
					t.Fatalf("unexpected source-route error IPv4 header: %+v", outer)
				}
				icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
				if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 5) || icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
					t.Fatalf("unexpected source-route error ICMP: %+v", icmp)
				}
				quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
				if quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4); !ok || !quotedIP.SrcIP.Equal(ipv4Source) || !quotedIP.DstIP.Equal(ipv4Dest) || len(quotedIP.Options) == 0 {
					t.Fatalf("source-route error did not quote the original IPv4 header: %v", quoted.ErrorLayer())
				}
				return
			}
			if err != nil {
				t.Fatalf("translation failed: %v", err)
			}
			packet := gopacket.NewPacket(result.packet, layers.LayerTypeIPv6, gopacket.Default)
			ip6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || packet.ErrorLayer() != nil {
				t.Fatalf("IPv4 option prevented translation: %v", packet.ErrorLayer())
			}
			// Payload Length is the IPv4 Total Length minus the IPv4 header *and* options (RFC 7915 Section 4.1),
			// and no IPv6 extension header is produced for the options.
			if ip6.NextHeader != layers.IPProtocolTCP || int(ip6.Length) != 20+len("opt") || len(result.packet) != ipv6HeaderLength+20+len("opt") {
				t.Fatalf("IPv4 options leaked into the IPv6 packet: next header %d, payload length %d, packet length %d", ip6.NextHeader, ip6.Length, len(result.packet))
			}
			tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok || !bytes.Equal(tcp.Payload, []byte("opt")) || tcp.Checksum != recalculatedTCPChecksum(t, ip6, tcp) {
				t.Fatalf("TCP segment was not translated after ignoring options: %v", packet.ErrorLayer())
			}
		})
	}
}

// RFC 1812 Section 4.3.2.7 (MUST NOT): "An ICMP error message MUST NOT be sent as the result of receiving: ... An
// ICMP error message"
//
// Regression guard: an ICMPv4 error with an unexpired source route used to generate Source Route Failed.
func TestTranslateIPv4ICMPErrorWithSourceRouteIsDroppedSilently(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Dest, DstIP: ipv4Source,
		Options: []layers.IPv4Option{sourceRoute(131, 4), ipv4NOP},
	}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 3)}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(ipv4TCPPacket(t, defaultTTL).Data())), layers.LayerTypeIPv4, gopacket.Default)
	result, err := translateIPv4(t, testTranslator(), input)
	if result.packet != nil || result.reply != nil {
		t.Fatalf("ICMP error with a source route generated a reply: err=%v", err)
	}
}

// ipv6PacketWithHeaders builds an IPv6 packet whose payload is a chain of extension headers followed by an
// upper-layer segment; first is the Next Header value of the IPv6 header itself.
func ipv6PacketWithHeaders(t *testing.T, first layers.IPProtocol, headers, segment []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, TrafficClass: testTrafficClass, NextHeader: first, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(append(append([]byte{}, headers...), segment...))), layers.LayerTypeIPv6, gopacket.Default)
}

// Extension headers of 8 octets: Hop-by-Hop and Destination Options carry a PadN option, Routing a type and Segments Left.
func optionsHeader(next layers.IPProtocol) []byte { return []byte{byte(next), 0, 1, 4, 0, 0, 0, 0} }
func routingHeader(next layers.IPProtocol, segmentsLeft uint8) []byte {
	return []byte{byte(next), 0, 0, segmentsLeft, 0, 0, 0, 0}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// RFC 7915 Section 5.1 (MUST): "those IPv6 extension headers MUST be ignored (i.e., there is no attempt to translate
// the extension headers) and the packet translated normally."
//
// RFC 7915 Section 5.1 (SHOULD): "If a Routing header with a non-zero Segments Left field is present, then the packet
// MUST NOT be translated, and an ICMPv6 'parameter problem/erroneous header field encountered' (Type 4, Code 0) error
// message, with the Pointer field indicating the first byte of the Segments Left field, SHOULD be returned to the
// sender."
//
// The row "routing with segments left after hop-by-hop" is a regression guard: the Parameter Problem used to drop a
// leading Hop-by-Hop header from its quote. The Pointer counts the headers before the Routing header too.
func TestTranslateIPv6ExtensionHeaders(t *testing.T) {
	const tcp, hbh, dest, routing = layers.IPProtocolTCP, layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Destination, layers.IPProtocolIPv6Routing
	tests := []struct {
		name    string
		first   layers.IPProtocol
		headers []byte
		pointer uint32 // non-zero: expected Parameter Problem pointer
	}{
		{name: "hop-by-hop", first: hbh, headers: optionsHeader(tcp)},
		{name: "destination options", first: dest, headers: optionsHeader(tcp)},
		{name: "routing with no segments", first: routing, headers: routingHeader(tcp, 0)},
		{name: "hop-by-hop then destination options", first: hbh, headers: cat(optionsHeader(dest), optionsHeader(tcp))},
		{name: "routing then destination options", first: routing, headers: cat(routingHeader(dest, 0), optionsHeader(tcp))},
		{name: "hop-by-hop, routing and destination options", first: hbh, headers: cat(optionsHeader(routing), routingHeader(dest, 0), optionsHeader(tcp))},
		{name: "routing with segments left", first: routing, headers: routingHeader(tcp, 1), pointer: ipv6HeaderLength + 3},
		{name: "routing with segments left after hop-by-hop", first: hbh, headers: cat(optionsHeader(routing), routingHeader(tcp, 2)), pointer: ipv6HeaderLength + 8 + 3},
		{name: "routing with segments left before destination options", first: routing, headers: cat(routingHeader(dest, 1), optionsHeader(tcp)), pointer: ipv6HeaderLength + 3},
	}
	segment := ipv6TCPPacket(t, defaultTTL).Data()[ipv6HeaderLength:]
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv6PacketWithHeaders(t, test.first, test.headers, segment)
			result, err := translateIPv6(t, testTranslator(), input)
			if test.pointer != 0 {
				if err == nil || result.reply == nil {
					t.Fatalf("routing header with segments left was not rejected with an ICMPv6 error: err=%v", err)
				}
				packet := gopacket.NewPacket(result.reply, layers.LayerTypeIPv6, gopacket.Default)
				icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
				if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0) {
					t.Fatalf("wrong ICMPv6 error for routing header: %+v", icmp)
				}
				if got := icmpPointerValue(t, icmp.Payload); got != test.pointer {
					t.Fatalf("pointer is %d, want %d", got, test.pointer)
				}
				// RFC 4443 Section 3.4: the invoking packet is quoted.
				quoted := icmpv6ErrorQuote(t, packet)
				if len(quoted.Data()) != len(input.Data()) || !bytes.Equal(quoted.Data(), input.Data()) {
					t.Fatalf("Parameter Problem does not quote the invoking packet: quoted %d bytes, packet %d", len(quoted.Data()), len(input.Data()))
				}
				return
			}
			if err != nil {
				t.Fatalf("translation failed: %v", err)
			}
			packet := gopacket.NewPacket(result.packet, layers.LayerTypeIPv4, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok {
				t.Fatalf("translated packet has no IPv4 layer: %v", packet.ErrorLayer())
			}
			if ip.Protocol != layers.IPProtocolTCP || ip.Length != uint16(len(result.packet)) || ip.Checksum != ipv4HeaderChecksum(ip) {
				t.Fatalf("IPv6 extension headers were not removed from the IPv4 packet: %+v", ip)
			}
			translatedTCP, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok || !bytes.Equal(translatedTCP.Payload, []byte("hello")) || translatedTCP.Checksum != recalculatedTCPChecksum(t, ip, translatedTCP) {
				t.Fatalf("IPv6 extension translation changed the TCP segment: %v", packet.ErrorLayer())
			}
		})
	}
}

// RFC 8200 Section 3: octets after the Payload Length are not translated, also behind a Hop-by-Hop header.
func TestTranslateIPv6IgnoresOctetsAfterPayloadLength(t *testing.T) {
	segment := ipv6TCPPacket(t, defaultTTL).Data()[ipv6HeaderLength:]
	tests := []struct {
		name    string
		first   layers.IPProtocol
		headers []byte
	}{
		{name: "without extension headers", first: layers.IPProtocolTCP},
		{name: "behind a hop-by-hop header", first: layers.IPProtocolIPv6HopByHop, headers: optionsHeader(layers.IPProtocolTCP)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := cat(ipv6PacketWithHeaders(t, test.first, test.headers, segment).Data(), bytes.Repeat([]byte{0x5a}, 8))
			result, err := translateIPv6(t, testTranslator(), gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default))
			if err != nil {
				t.Fatalf("translation failed: %v", err)
			}
			if len(result.packet) != ipv4HeaderLength+len(segment) {
				t.Fatalf("translated packet is %d octets, want %d", len(result.packet), ipv4HeaderLength+len(segment))
			}
		})
	}
}

// RFC 4443 Section 2.4 (MUST NOT): "An ICMPv6 error message MUST NOT be originated as a result of receiving the
// following: (e.1) An ICMPv6 error message."
//
// Regression guard: an ICMPv6 error behind a Routing header with Segments Left > 0 used to generate a Parameter
// Problem.
func TestTranslateIPv6ICMPErrorWithSegmentsLeftIsDroppedSilently(t *testing.T) {
	quote := ipv6TCPPacket(t, defaultTTL).Data()
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 4)}
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Dest, DstIP: ipv6Source}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	message := serializeTestPacket(t, icmp, gopacket.Payload(append(zeroRestHeader(), quote...)))
	input := ipv6PacketWithHeaders(t, layers.IPProtocolIPv6Routing, routingHeader(layers.IPProtocolICMPv6, 1), message)
	// The checksum covers the final destination, so recompute it for the packet as built.
	result, err := translateIPv6(t, testTranslator(), input)
	if result.packet != nil || result.reply != nil {
		t.Fatalf("ICMPv6 error behind a routing header generated a reply: err=%v", err)
	}
}

// Local robustness: a Total Length or Payload Length that does not match the packet is rejected.
func TestTranslateRejectsInconsistentPayloadLengths(t *testing.T) {
	tests := []struct {
		name      string
		packet    []byte
		layer     gopacket.LayerType
		lengthAt  int
		translate func(*testing.T, *siit.Translator, gopacket.Packet) (translation, error)
	}{
		{
			name: "IPv4 total length", packet: ipv4TCPPacket(t, defaultTTL).Data(), layer: layers.LayerTypeIPv4, lengthAt: 2,
			translate: translateIPv4,
		},
		{
			name: "IPv6 payload length", packet: ipv6TCPPacket(t, defaultTTL).Data(), layer: layers.LayerTypeIPv6, lengthAt: 4,
			translate: translateIPv6,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packetBytes := append([]byte(nil), test.packet...)
			binary.BigEndian.PutUint16(packetBytes[test.lengthAt:test.lengthAt+2], 1)
			input := gopacket.NewPacket(packetBytes, test.layer, gopacket.Default)
			if _, err := test.translate(t, testTranslator(), input); err == nil {
				t.Fatal("inconsistent payload length was accepted")
			}
		})
	}
}

// RFC 7915 Section 4.1 (SHOULD): "If the translator gets an illegal source address (e.g., 0.0.0.0, 127.0.0.1, etc.),
// the translator SHOULD silently discard the packet"
//
// RFC 7915 Section 5.1 (SHOULD): "If the translator gets an illegal source address (e.g., ::1, etc.), the translator
// SHOULD silently drop the packet."
//
// Illegal destinations are rejected as well (local rule: unicast only).
func TestTranslateRejectsIllegalAddresses(t *testing.T) {
	ipv4Illegal := []string{"0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "239.255.255.250", "255.255.255.255"}
	ipv6Illegal := []string{"::", "::1", "fe80::1", "ff02::1", "ff05::2"}
	translators := map[string]*siit.Translator{
		"well-known prefix":           testTranslator(),
		"network-specific prefix":     translatorWithPrefix(t, "2001:db8:64::/96", nil),
		"network-specific /64 mapped": translatorWithPrefix(t, "2001:db8:64::/64", nil),
	}
	for name, translator := range translators {
		for _, address := range ipv4Illegal {
			ip := net.ParseIP(address).To4()
			for _, test := range []struct {
				side   string
				packet gopacket.Packet
			}{
				{"source", ipv4TCPPacketWithAddresses(t, defaultTTL, ip, ipv4Dest)},
				{"destination", ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, ip)},
			} {
				t.Run(fmt.Sprintf("%s/IPv4 %s %s", name, test.side, address), func(t *testing.T) {
					result, err := translateIPv4(t, translator, test.packet)
					if err == nil || result.packet != nil {
						t.Fatalf("illegal IPv4 %s %s was not rejected: result length=%d err=%v", test.side, address, len(result.packet), err)
					}
				})
			}
		}
		for _, address := range ipv6Illegal {
			ip := net.ParseIP(address)
			for _, test := range []struct {
				side   string
				packet gopacket.Packet
			}{
				{"source", ipv6TCPPacketWithAddresses(t, defaultTTL, ip, ipv6Dest)},
				{"destination", ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, ip)},
			} {
				t.Run(fmt.Sprintf("%s/IPv6 %s %s", name, test.side, address), func(t *testing.T) {
					result, err := translateIPv6(t, translator, test.packet)
					if err == nil || result.packet != nil {
						t.Fatalf("illegal IPv6 %s %s was not rejected: result length=%d err=%v", test.side, address, len(result.packet), err)
					}
				})
			}
		}
	}
}

// RFC 7915 Sections 4.1 and 5.1 (MUST): "the translator (as any router) MUST check for zero and send the ICMPv4 'TTL
// Exceeded' or ICMPv6 'Hop Limit Exceeded' error."
//
// ICMP errors never trigger another ICMP error (RFC 4443 Section 2.4, RFC 1122 Section 3.2.2).
func TestTranslateExpiredTTL(t *testing.T) {
	for _, ttl := range []uint8{0, 1} {
		t.Run(fmt.Sprintf("IPv4 TTL %d", ttl), func(t *testing.T) {
			result, err := translateIPv4(t, testTranslator(), ipv4TCPPacket(t, ttl))
			if !errors.Is(err, siit.ErrTimeExceeded) {
				t.Fatalf("got error %v, want ErrTimeExceeded", err)
			}
			if result.reply == nil {
				t.Fatalf("no Time Exceeded reply was generated: %T", err)
			}
			packet := gopacket.NewPacket(result.reply, layers.LayerTypeIPv6, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || ip.NextHeader != layers.IPProtocolICMPv6 || !ip.DstIP.Equal(ipv4TranslatedSource) {
				t.Fatalf("missing generated IPv6 ICMP error to the sender: %v", packet.ErrorLayer())
			}
			icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(icmpv6TimeExceeded, 0) || icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
				t.Fatalf("invalid generated IPv6 Time Exceeded: %v", packet.ErrorLayer())
			}
			quoted, ok := icmpv6ErrorQuote(t, packet).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || quoted.HopLimit != ttl {
				t.Fatalf("generated quote has Hop Limit %v, want %d", quoted, ttl)
			}
		})

		t.Run(fmt.Sprintf("IPv6 Hop Limit %d", ttl), func(t *testing.T) {
			result, err := translateIPv6(t, testTranslator(), ipv6TCPPacketWithAddresses(t, ttl, ipv6Dest, ipv6Source))
			if !errors.Is(err, siit.ErrTimeExceeded) {
				t.Fatalf("got error %v, want ErrTimeExceeded", err)
			}
			if result.reply == nil {
				t.Fatalf("no Time Exceeded reply was generated: %T", err)
			}
			packet := gopacket.NewPacket(result.reply, layers.LayerTypeIPv4, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ip.Protocol != layers.IPProtocolICMPv4 || ip.Checksum != ipv4HeaderChecksum(ip) {
				t.Fatalf("invalid generated IPv4 ICMP error: %v", packet.ErrorLayer())
			}
			icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(icmpv4TimeExceeded, 0) || icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
				t.Fatalf("invalid generated IPv4 Time Exceeded: %v", packet.ErrorLayer())
			}
			quoted, ok := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || quoted.TTL != ttl {
				t.Fatalf("generated quote has TTL %v, want %d", quoted, ttl)
			}
		})
	}

	// Other transport protocols expire like TCP; an expiring ICMP error is dropped without any reply.
	for _, test := range []struct {
		name    string
		v4      gopacket.Packet
		v6      gopacket.Packet
		dropped bool
	}{
		{name: "UDP", v4: ipv4Segment(t, segmentUDP, ipv4Source, ipv4Dest, 1), v6: ipv6Segment(t, segmentUDP, ipv6Dest, ipv6Source, 1)},
		{name: "ICMP echo", v4: ipv4Segment(t, segmentICMP, ipv4Source, ipv4Dest, 1), v6: ipv6Segment(t, segmentICMP, ipv6Dest, ipv6Source, 1)},
		{name: "ICMP error", v4: withTTL(t, ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, ipv4TCPPacket(t, defaultTTL).Data()), 1),
			v6: withHopLimit(t, ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, ipv6TCPPacket(t, defaultTTL).Data()), 1), dropped: true},
	} {
		t.Run(test.name+" with TTL 1", func(t *testing.T) {
			for direction, translate := range map[string]func() (translation, error){
				"IPv4": func() (translation, error) {
					return translateIPv4(t, testTranslator(), test.v4)
				},
				"IPv6": func() (translation, error) {
					return translateIPv6(t, testTranslator(), test.v6)
				},
			} {
				result, err := translate()
				if test.dropped {
					if result.packet != nil || result.reply != nil {
						t.Fatalf("%s: expired ICMP error generated a reply: err=%v", direction, err)
					}
					continue
				}
				if !errors.Is(err, siit.ErrTimeExceeded) || result.reply == nil {
					t.Fatalf("%s: expired %s did not generate Time Exceeded: err=%v", direction, test.name, err)
				}
			}
		})
	}
}

// RFC 7915 Section 5.1: "Identification: Set according to a Fragment Identification generator at the translator."
//
// The generator follows RFC 7739 Section 5.3. With 16 bits, random values would repeat within a few hundred packets.
func TestTranslateIPv6ToIPv4IdentificationDoesNotRepeatPerDestination(t *testing.T) {
	translator := testTranslator()
	seen := map[uint16]bool{}
	for range 1000 {
		id := translatedIdentification(t, translator, ipv6Dest)
		if seen[id] {
			t.Fatalf("Identification %#x repeated within 1000 packets to one destination", id)
		}
		seen[id] = true
	}
}

// RFC 7739 Section 3 describes the attacks on predictable Identification values: one global counter would reveal the
// translator's packet rate and the values sent to other destinations.
func TestTranslateIPv6ToIPv4IdentificationIsUnrelatedAcrossDestinations(t *testing.T) {
	translator := testTranslator()
	previous := translatedIdentification(t, translator, ipv6Dest)
	for i := range 8 {
		destination := net.ParseIP(fmt.Sprintf("64:ff9b::101:%x", 0x102+i)) // 1.1.1.2 and up
		id := translatedIdentification(t, translator, destination)
		if id != previous+1 {
			return
		}
		previous = id
	}
	t.Fatal("successive packets to different destinations carry consecutive Identification values")
}

func translatedIdentification(t *testing.T, translator *siit.Translator, destination net.IP) uint16 {
	t.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolGRE, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: destination}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() (translation, error) {
		return translateIPv6(t, translator, input)
	})
	return binary.BigEndian.Uint16(result[4:6])
}

// RFC 7915 Section 5.1 (SHOULD): "If the translator gets an illegal source address (e.g., ::1, etc.), the translator
// SHOULD silently drop the packet."
//
// With a Network-Specific Prefix, an IPv6 address can embed an illegal IPv4 address (RFC 1812 Section 5.3.7). It is
// rejected as a source and, as a local rule, as a destination. Explicit address mappings (RFC 7757) are exempt.
func TestTranslateRejectsIllegalEmbeddedIPv4Addresses(t *testing.T) {
	embed := func(prefix string, address string) net.IP {
		ipv4 := net.ParseIP(address).To4()
		ipv6 := net.ParseIP(prefix).To16()
		if prefix == "2001:db8:64::" {
			copy(ipv6[12:], ipv4)
		} else {
			copy(ipv6[9:], ipv4) // /64: the IPv4 address follows the zero u octet
		}
		return ipv6
	}
	translators := map[string]struct {
		translator *siit.Translator
		prefix     string
	}{
		"network-specific /96": {translatorWithPrefix(t, "2001:db8:64::/96", nil), "2001:db8:64::"},
		"network-specific /64": {translatorWithPrefix(t, "2001:db8:64:64::/64", nil), "2001:db8:64:64::"},
	}
	global := "198.51.100.7"
	for name, setup := range translators {
		prefix := setup.prefix
		for _, address := range []string{"0.0.0.0", "127.0.0.1", "127.1.1.1", "169.254.0.42", "224.0.0.1", "239.255.255.250", "255.255.255.255"} {
			t.Run(fmt.Sprintf("%s/source %s", name, address), func(t *testing.T) {
				packet := ipv6TCPPacketWithAddresses(t, defaultTTL, embed(prefix, address), embed(prefix, global))
				result, err := translateIPv6(t, setup.translator, packet)
				if !errors.Is(err, siit.ErrUnsupportedSrcIP) || result.packet != nil {
					t.Fatalf("got err=%v, packet length %d, want ErrUnsupportedSrcIP", err, len(result.packet))
				}
			})
			t.Run(fmt.Sprintf("%s/destination %s", name, address), func(t *testing.T) {
				packet := ipv6TCPPacketWithAddresses(t, defaultTTL, embed(prefix, global), embed(prefix, address))
				result, err := translateIPv6(t, setup.translator, packet)
				if !errors.Is(err, siit.ErrUnsupportedDestIP) || result.packet != nil {
					t.Fatalf("got err=%v, packet length %d, want ErrUnsupportedDestIP", err, len(result.packet))
				}
			})
		}
		t.Run(name+"/global addresses still translate", func(t *testing.T) {
			packet := ipv6TCPPacketWithAddresses(t, defaultTTL, embed(prefix, global), embed(prefix, "203.0.113.9"))
			result, err := translateIPv6(t, setup.translator, packet)
			if err != nil || result.packet == nil {
				t.Fatalf("legal embedded addresses were rejected: %v", err)
			}
		})
	}

	t.Run("explicit address mappings are exempt", func(t *testing.T) {
		translator := translatorWithPrefix(t, "2001:db8:64::/96", rawEAMTable{{IPv4Prefix: "127.0.0.9/32", IPv6Prefix: "2001:db8:eeee::9/128"}})
		packet := ipv6TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("2001:db8:eeee::9"), embed("2001:db8:64::", global))
		result, err := translateIPv6(t, translator, packet)
		if err != nil || result.packet == nil {
			t.Fatalf("EAM-mapped address was rejected: %v", err)
		}
	})
}

// RFC 7915 Section 4.1: the IPv4 Protocol field is translated to the IPv6 Next Header field. The IPv6 extension
// headers Hop-by-Hop (0), Routing (43), Fragment (44) and Destination Options (60) have no IPv4 equivalent, and
// copying them would make the receiver parse the payload as an extension header. Such packets are rejected, whole or
// fragmented, while ordinary and unknown protocol numbers are forwarded unchanged.
func TestTranslateRejectsIPv6ExtensionHeaderProtocolNumbers(t *testing.T) {
	translate := func(t *testing.T, protocol layers.IPProtocol, flags layers.IPv4Flag) (translation, error) {
		t.Helper()
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: protocol, Flags: flags, SrcIP: ipv4Source, DstIP: ipv4Dest}
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 64))), layers.LayerTypeIPv4, gopacket.Default)
		return translateIPv4(t, testTranslator(), input)
	}
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Fragment, layers.IPProtocolIPv6Destination} {
		for name, flags := range map[string]layers.IPv4Flag{"whole": 0, "more fragments": layers.IPv4MoreFragments} {
			t.Run(fmt.Sprintf("protocol %d %s", protocol, name), func(t *testing.T) {
				result, err := translate(t, protocol, flags)
				if !errors.Is(err, siit.ErrUnsupportedProtocol) || result.packet != nil {
					t.Fatalf("got err=%v, packet length %d, want ErrUnsupportedProtocol", err, len(result.packet))
				}
			})
		}
	}
	for _, protocol := range []layers.IPProtocol{16, 69, 135, 253} {
		t.Run(fmt.Sprintf("protocol %d is forwarded", protocol), func(t *testing.T) {
			result, err := translate(t, protocol, 0)
			if err != nil || result.packet == nil {
				t.Fatalf("ordinary protocol was rejected: %v", err)
			}
			if result.packet[6] != byte(protocol) {
				t.Fatalf("Next Header = %d, want %d", result.packet[6], protocol)
			}
		})
	}
}
