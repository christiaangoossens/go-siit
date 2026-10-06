package siit_test

import (
	"bytes"
	"errors"
	"fmt"
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
			result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			if result.Packet != nil || err == nil {
				t.Fatalf("malformed payload was accepted: err=%v", err)
			}
		})
	}
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP, layers.IPProtocolICMPv6} {
		t.Run(fmt.Sprintf("IPv6 protocol %d with a 3-octet payload", protocol), func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: protocol, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload([]byte{1, 2, 3})), layers.LayerTypeIPv6, gopacket.Default)
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			if result.Packet != nil || !errors.Is(err, siit.ErrInvalidPacket) {
				t.Fatalf("malformed payload returned %v, want ErrInvalidPacket", err)
			}
		})
	}
	t.Run("truncated IPv4 header", func(t *testing.T) {
		result, err := testTranslator().TranslateIPv4(gopacket.NewPacket([]byte{0x45, 0, 0, 20}, layers.LayerTypeIPv4, gopacket.Default), siit.TranslationOverrides{})
		if result.Packet != nil || err == nil {
			t.Fatalf("truncated IPv4 header was accepted: err=%v", err)
		}
	})
	t.Run("truncated IPv6 header", func(t *testing.T) {
		result, err := testTranslator().TranslateIPv6(gopacket.NewPacket([]byte{0x60, 0, 0, 0}, layers.LayerTypeIPv6, gopacket.Default), siit.TranslationOverrides{})
		if result.Packet != nil || err == nil {
			t.Fatalf("truncated IPv6 header was accepted: err=%v", err)
		}
	})
}

// Local API contract: exported sentinel errors classify invalid input and unsupported protocols.
func TestTranslateReturnsSpecificErrors(t *testing.T) {
	notIP := gopacket.NewPacket([]byte{0}, gopacket.LayerTypePayload, gopacket.Default)
	if _, err := testTranslator().TranslateIPv4(notIP, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrInvalidPacket) {
		t.Fatalf("missing IPv4 layer returned %v, want ErrInvalidPacket", err)
	}
	if _, err := testTranslator().TranslateIPv6(notIP, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrInvalidPacket) {
		t.Fatalf("missing IPv6 layer returned %v, want ErrInvalidPacket", err)
	}

	// Fragmented ICMPv4 is the one case where an otherwise valid packet is reported as an unsupported protocol.
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Flags: layers.IPv4MoreFragments, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	unsupported := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv4, gopacket.Default)
	if _, err := testTranslator().TranslateIPv4(unsupported, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrUnsupportedProtocol) {
		t.Fatalf("fragmented ICMPv4 returned %v, want ErrUnsupportedProtocol", err)
	}
}

// RFC 7915 Sections 4.1, 5.1 and 5.5 (MUST: "translators MUST forward all transport protocols"): protocols other than
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

// RFC 7915 Section 4.2 (SHOULD): "normal" IGMP messages are single-hop messages and are silently dropped.
func TestTranslateDropsIGMP(t *testing.T) {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolIGMP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	requireDropped(t, result, err)
}
