package siit_test

import (
	"bytes"
	"fmt"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.2, 4.5, 5.2, and 5.5: echo messages translate in both directions with valid checksums.
func TestTranslateICMPEchoBothDirections(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
		messageID   uint16
		sequence    uint16
		payload     []byte
		ipv6Type    uint8
	}{
		{name: "request", messageType: echoRequest, messageID: 0x1234, sequence: 7, payload: []byte("echo"), ipv6Type: 128},
		{name: "reply", messageType: echoReply, messageID: 0x4321, sequence: 9, payload: []byte("reply"), ipv6Type: 129},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
			icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(test.messageType, 0), Id: test.messageID, Seq: test.sequence}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(test.payload)), layers.LayerTypeIPv4, gopacket.Default)
			translated6 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet6 := gopacket.NewPacket(translated6, layers.LayerTypeIPv6, gopacket.Default)
			icmp6, ok := packet6.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok || icmp6.TypeCode.Type() != test.ipv6Type || icmp6.Checksum == 0 {
				t.Fatalf("IPv4 ICMP %s was not translated with a checksum: %v", test.name, packet6.ErrorLayer())
			}
			echo6, ok := packet6.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
			if !ok || echo6.Identifier != test.messageID || echo6.SeqNumber != test.sequence || !bytes.HasSuffix(packet6.Data(), test.payload) {
				t.Fatalf("IPv4 ICMP %s echo data changed: %+v", test.name, echo6)
			}
			if icmp6.Checksum != recalculatedICMPv6Checksum(t, packet6.Layer(layers.LayerTypeIPv6).(*layers.IPv6), icmp6) {
				t.Fatalf("IPv4 ICMP %s checksum is invalid: %#x", test.name, icmp6.Checksum)
			}

			translated4 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(packet6, siit.TranslationOverrides{})
			})
			packet4 := gopacket.NewPacket(translated4, layers.LayerTypeIPv4, gopacket.Default)
			icmp4, ok := packet4.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || icmp4.TypeCode.Type() != test.messageType || icmp4.Id != test.messageID || icmp4.Seq != test.sequence || icmp4.Checksum == 0 || !bytes.HasSuffix(packet4.Data(), test.payload) {
				t.Fatalf("ICMPv6 %s was not translated back with its fields and checksum: %v", test.name, packet4.ErrorLayer())
			}
			if icmp4.Checksum != recalculatedICMPv4Checksum(t, icmp4) {
				t.Fatalf("ICMPv6 %s checksum is invalid: %#x", test.name, icmp4.Checksum)
			}
		})
	}
}

// Local policy (RFC 792 defines Echo Code 0 only; RFC 7915 does not specify other codes): a nonzero code is rejected.
func TestTranslateICMPEchoRejectsNonzeroCode(t *testing.T) {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(echoRequest, 1), Id: 1, Seq: 1}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp), layers.LayerTypeIPv4, gopacket.Default)
	if _, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{}); err == nil {
		t.Fatal("ICMPv4 Echo Request with a nonzero code was accepted")
	}
}

// Local policy (RFC 4443 Section 4.1 defines Echo Code 0 only; RFC 7915 does not specify other codes): a nonzero code is rejected.
func TestTranslateICMPv6EchoRejectsNonzeroCode(t *testing.T) {
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 1)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload([]byte("echo"))), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	requireRejected(t, result, err)
}

// RFC 7915 Figures 3 and 6 with RFC 792 / RFC 4443: ICMPv4 carries the Parameter Problem pointer in
// octet 4 of the message; ICMPv6 carries a 32-bit pointer in the type-specific word.
func TestTranslateICMPParameterProblemPointers(t *testing.T) {

	ipv4ToIPv6 := []struct {
		name string
		from uint8
		to   uint32
	}{
		{name: "version", from: 0, to: 0},
		{name: "traffic class", from: 1, to: 1},
		{name: "total length high", from: 2, to: 4},
		{name: "total length low", from: 3, to: 4},
		{name: "time to live", from: 8, to: 7},
		{name: "protocol", from: 9, to: 6},
		{name: "source address first", from: 12, to: 8},
		{name: "source address last", from: 15, to: 8},
		{name: "destination address first", from: 16, to: 24},
		{name: "destination address last", from: 19, to: 24},
	}
	for _, test := range ipv4ToIPv6 {
		t.Run("IPv4 to IPv6 "+test.name, func(t *testing.T) {
			input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeParameterProblem, 0, uint16(test.from)<<8, 0, ipv4TCPPacket(t, defaultTTL).Data())
			result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			if err != nil || result.Packet == nil {
				t.Fatalf("Parameter Problem pointer %d was not translated: err=%v", test.from, err)
			}
			packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
			translated, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok || translated.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0) {
				t.Fatalf("missing translated ICMPv6 Parameter Problem: %v", packet.ErrorLayer())
			}
			if got := icmpPointerValue(t, translated.Payload); got != test.to {
				t.Fatalf("mapped pointer %d to %d, want %d", test.from, got, test.to)
			}
		})
	}

	ipv6ToIPv4 := []struct {
		name string
		from uint32
		to   uint8
	}{
		{name: "version", from: 0, to: 0},
		{name: "traffic class", from: 1, to: 1},
		{name: "payload length high", from: 4, to: 2},
		{name: "payload length low", from: 5, to: 2},
		{name: "next header", from: 6, to: 9},
		{name: "hop limit", from: 7, to: 8},
		{name: "source address first", from: 8, to: 12},
		{name: "source address last", from: 23, to: 12},
		{name: "destination address first", from: 24, to: 16},
		{name: "destination address last", from: 39, to: 16},
	}
	for _, test := range ipv6ToIPv4 {
		t.Run("IPv6 to IPv4 "+test.name, func(t *testing.T) {
			input := ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypeParameterProblem, 0, icmpPointer(test.from), ipv6TCPPacket(t, defaultTTL).Data())
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			if err != nil || result.Packet == nil {
				t.Fatalf("Parameter Problem pointer %d was not translated: err=%v", test.from, err)
			}
			packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default)
			translated, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || translated.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeParameterProblem, 0) {
				t.Fatalf("missing translated ICMPv4 Parameter Problem: %v", packet.ErrorLayer())
			}
			if got := uint8(translated.Id >> 8); got != test.to {
				t.Fatalf("mapped pointer %d to %d in ICMPv4 octet 4, want %d", test.from, got, test.to)
			}
			if quote := gopacket.NewPacket(translated.Payload, layers.LayerTypeIPv4, gopacket.Default); quote.Layer(layers.LayerTypeIPv4) == nil {
				t.Fatalf("translated Parameter Problem does not quote the original packet: %v", quote.ErrorLayer())
			}
		})
	}
}

// RFC 7915 Figures 3 and 6: pointers marked "n/a" (or outside the listed ranges) cause a silent drop.
func TestTranslateICMPParameterProblemUnmappablePointersDropped(t *testing.T) {
	for _, pointer := range []uint8{4, 5, 6, 7, 10, 11, 20, 255} {
		t.Run(fmt.Sprintf("IPv4 pointer %d", pointer), func(t *testing.T) {
			input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeParameterProblem, 0, uint16(pointer)<<8, 0, ipv4TCPPacket(t, defaultTTL).Data())
			result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			requireDropped(t, result, err)
		})
	}
	for _, pointer := range []uint32{2, 3, 40, 1000} {
		t.Run(fmt.Sprintf("IPv6 pointer %d", pointer), func(t *testing.T) {
			input := ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypeParameterProblem, 0, icmpPointer(pointer), ipv6TCPPacket(t, defaultTTL).Data())
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			requireDropped(t, result, err)
		})
	}
}

// RFC 7915 Section 4.2: Destination Unreachable code 2 becomes Parameter Problem code 1 pointing at Next Header (6).
func TestTranslateICMPProtocolUnreachablePointsAtNextHeader(t *testing.T) {
	input := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 2, ipv4TCPPacket(t, defaultTTL).Data())
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 1) {
		t.Fatalf("unexpected translation of Protocol Unreachable: %v", packet.ErrorLayer())
	}
	if got := icmpPointerValue(t, icmp.Payload); got != 6 {
		t.Fatalf("pointer is %d, want 6 (IPv6 Next Header)", got)
	}
}
