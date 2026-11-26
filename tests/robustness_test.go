package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Local robustness (RFC 7915 Sections 4.5 and 5.5 for the transport headers): truncated IP headers and transport or
// ICMP messages that are too short to hold their header are rejected with ErrInvalidPacket, never translated and
// never a panic.
func TestTranslateRejectsMalformedPackets(t *testing.T) {
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP, layers.IPProtocolICMPv4} {
		t.Run(fmt.Sprintf("IPv4 protocol %d with a 3-octet payload", protocol), func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: protocol, SrcIP: ipv4Source, DstIP: ipv4Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload([]byte{1, 2, 3})), layers.LayerTypeIPv4, gopacket.Default)
			result, err := translateIPv4(t, testTranslator(), input)
			if result.packet != nil || err == nil {
				t.Fatalf("malformed payload was accepted: err=%v", err)
			}
		})
	}
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP, layers.IPProtocolICMPv6} {
		t.Run(fmt.Sprintf("IPv6 protocol %d with a 3-octet payload", protocol), func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: protocol, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload([]byte{1, 2, 3})), layers.LayerTypeIPv6, gopacket.Default)
			result, err := translateIPv6(t, testTranslator(), input)
			if result.packet != nil || !errors.Is(err, siit.ErrInvalidPacket) {
				t.Fatalf("malformed payload returned %v, want ErrInvalidPacket", err)
			}
		})
	}

	t.Run("ICMPv4 message shorter than its header", func(t *testing.T) {
		message := []byte{echoRequest, 0, 0, 0}
		binary.BigEndian.PutUint16(message[icmpChecksumOffset:], checksum(message))
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(message)), layers.LayerTypeIPv4, gopacket.Default)
		result, err := translateIPv4(t, testTranslator(), input)
		requireRejected(t, result, err)
	})
	t.Run("ICMPv6 message shorter than its header", func(t *testing.T) {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
		if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp), layers.LayerTypeIPv6, gopacket.Default)
		result, err := translateIPv6(t, testTranslator(), input)
		requireRejected(t, result, err)
	})

	// Destination Options header that declares 16 octets but holds 8.
	t.Run("truncated extension header after Hop-by-Hop", func(t *testing.T) {
		truncated := []byte{byte(layers.IPProtocolTCP), 1, 1, 4, 0, 0, 0, 0}
		input := ipv6PacketWithHeaders(t, layers.IPProtocolIPv6HopByHop, optionsHeader(layers.IPProtocolIPv6Destination), truncated)
		result, err := translateIPv6(t, testTranslator(), input)
		if result.packet != nil || !errors.Is(err, siit.ErrInvalidPacket) {
			t.Fatalf("truncated extension header returned %v, want ErrInvalidPacket", err)
		}
	})
	t.Run("Payload Length shorter than the Hop-by-Hop header", func(t *testing.T) {
		segment := ipv6TCPPacket(t, defaultTTL).Data()[ipv6HeaderLength:]
		data := slices.Clone(ipv6PacketWithHeaders(t, layers.IPProtocolIPv6HopByHop, optionsHeader(layers.IPProtocolTCP), segment).Data())
		binary.BigEndian.PutUint16(data[4:6], 4)
		result, err := translateIPv6(t, testTranslator(), gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default))
		if result.packet != nil || !errors.Is(err, siit.ErrInvalidPacket) {
			t.Fatalf("short Payload Length returned %v, want ErrInvalidPacket", err)
		}
	})

	t.Run("truncated IPv4 header", func(t *testing.T) {
		result, err := translateIPv4(t, testTranslator(), gopacket.NewPacket([]byte{0x45, 0, 0, 20}, layers.LayerTypeIPv4, gopacket.Default))
		if result.packet != nil || err == nil {
			t.Fatalf("truncated IPv4 header was accepted: err=%v", err)
		}
	})
	t.Run("truncated IPv6 header", func(t *testing.T) {
		result, err := translateIPv6(t, testTranslator(), gopacket.NewPacket([]byte{0x60, 0, 0, 0}, layers.LayerTypeIPv6, gopacket.Default))
		if result.packet != nil || err == nil {
			t.Fatalf("truncated IPv6 header was accepted: err=%v", err)
		}
	})
}

// Local API contract: exported sentinel errors classify invalid input and unsupported protocols.
func TestTranslateReturnsSpecificErrors(t *testing.T) {
	notIP := gopacket.NewPacket([]byte{0}, gopacket.LayerTypePayload, gopacket.Default)
	if _, err := translateIPv4(t, testTranslator(), notIP); !errors.Is(err, siit.ErrInvalidPacket) {
		t.Fatalf("missing IPv4 layer returned %v, want ErrInvalidPacket", err)
	}
	if _, err := translateIPv6(t, testTranslator(), notIP); !errors.Is(err, siit.ErrInvalidPacket) {
		t.Fatalf("missing IPv6 layer returned %v, want ErrInvalidPacket", err)
	}

	// Fragmented ICMPv4 is the one case where an otherwise valid packet is reported as an unsupported protocol.
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Flags: layers.IPv4MoreFragments, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	unsupported := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv4, gopacket.Default)
	if _, err := translateIPv4(t, testTranslator(), unsupported); !errors.Is(err, siit.ErrUnsupportedProtocol) {
		t.Fatalf("fragmented ICMPv4 returned %v, want ErrUnsupportedProtocol", err)
	}
}

// RFC 7915 Sections 4.5 and 5.5 (MUST: "translators MUST forward all transport protocols"): protocols other than
// TCP, UDP and ICMP are forwarded with their payload unchanged, including payloads too short to contain a
// recognizable header, and behind IPv6 extension headers that are skipped.
func TestTranslateForwardsOtherProtocols(t *testing.T) {
	protocols := map[string]layers.IPProtocol{"GRE": layers.IPProtocolGRE, "ESP": layers.IPProtocolESP, "SCTP": layers.IPProtocolSCTP, "UDP-Lite": layers.IPProtocolUDPLite, "experimental": 253}
	for name, protocol := range protocols {
		for _, size := range []int{3, 4, 64, 1000} {
			payload := bytes.Repeat([]byte{0x5a}, size)
			t.Run(fmt.Sprintf("IPv4 to IPv6/%s/%d octets", name, size), func(t *testing.T) {
				ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: protocol, SrcIP: ipv4Source, DstIP: ipv4Dest}
				input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
				ip6 := translateIPv4Raw(t, input.Data()).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				if ip6.NextHeader != protocol || !bytes.Equal(ip6.Payload, payload) {
					t.Fatalf("payload was not forwarded unchanged: %+v", ip6)
				}
			})
			t.Run(fmt.Sprintf("IPv6 to IPv4/%s/%d octets", name, size), func(t *testing.T) {
				for _, headers := range [][]byte{nil, optionsHeader(protocol)} {
					first := protocol
					if headers != nil {
						first = layers.IPProtocolIPv6HopByHop
					}
					input := ipv6PacketWithHeaders(t, first, headers, payload)
					ip4 := translateToIPv4Packet(t, input).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
					if ip4.Protocol != protocol || !bytes.Equal(ip4.Payload, payload) {
						t.Fatalf("payload was not forwarded unchanged: %+v", ip4)
					}
				}
			})
		}
	}
}

// No Next Header (59) is forwarded like any other protocol, also without a payload. A Payload Length of 0 without a
// Jumbo Payload option is a valid empty packet, but gopacket reads it as a jumbogram, so TranslateIPv6 rejects it.
func TestTranslateForwardsNoNextHeader(t *testing.T) {
	input := ipv6PacketWithHeaders(t, layers.IPProtocolNoNextHeader, nil, nil)

	ip4 := translateToIPv4Packet(t, input).Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	if ip4.Protocol != layers.IPProtocolNoNextHeader || ip4.Length != ipv4HeaderLength {
		t.Fatalf("got protocol %d and Total Length %d, want 59 and %d", ip4.Protocol, ip4.Length, ipv4HeaderLength)
	}
}

// RFC 7915 Section 4.2 (SHOULD): "IGMP messages are single-hop messages and SHOULD be silently dropped by the
// translator."
func TestTranslateDropsIGMP(t *testing.T) {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolIGMP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv4, gopacket.Default)
	result, err := translateIPv4(t, testTranslator(), input)
	requireDropped(t, result, err)
}
