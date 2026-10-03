package siit_test

import (
	"bytes"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ipv4ICMPPacket(t *testing.T, messageType, code uint8, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(messageType, code)}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

func ipv6ICMPPacket(t *testing.T, messageType, code uint8, payload []byte) gopacket.Packet {
	return ipv6ICMPPacketWithRestHeader(t, messageType, code, make([]byte, icmpErrorRestHeaderSize), payload)
}

func ipv6ICMPPacketWithRestHeader(t *testing.T, messageType, code uint8, restHeader, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(messageType, code)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	if len(restHeader) != icmpErrorRestHeaderSize {
		t.Fatalf("ICMPv6 rest header must be %d bytes, got %d", icmpErrorRestHeaderSize, len(restHeader))
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(append(restHeader, payload...))), layers.LayerTypeIPv6, gopacket.Default)
}

// RFC 7915 Section 4.2: non-Internet IPv4 control queries and unknown types are silently dropped individually.
func TestTranslateDropsUnsupportedIPv4ICMPQueriesIndividually(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
	}{
		{name: "router advertisement", messageType: layers.ICMPv4TypeRouterAdvertisement},
		{name: "router solicitation", messageType: layers.ICMPv4TypeRouterSolicitation},
		{name: "timestamp request", messageType: layers.ICMPv4TypeTimestampRequest},
		{name: "timestamp reply", messageType: layers.ICMPv4TypeTimestampReply},
		{name: "information request", messageType: layers.ICMPv4TypeInfoRequest},
		{name: "information reply", messageType: layers.ICMPv4TypeInfoReply},
		{name: "address mask request", messageType: layers.ICMPv4TypeAddressMaskRequest},
		{name: "address mask reply", messageType: layers.ICMPv4TypeAddressMaskReply},
		{name: "IGMP", messageType: 0x22},
		{name: "unknown", messageType: 255},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv4ICMPPacket(t, test.messageType, 0, bytes.Repeat([]byte{0}, 8))
			result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			requireDropped(t, result, err)
		})
	}
}

// RFC 7915 Section 4.2: normal IGMP messages are silently dropped.
func TestTranslateDropsIGMP(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolIGMP,
		SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(bytes.Repeat([]byte{0}, 8))), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	requireDropped(t, result, err)
}

// RFC 7915 Section 5.2: MLD, Neighbor Discovery, Router Discovery, Redirect, and other internal control messages are silently dropped individually.
func TestTranslateDropsUnsupportedIPv6ControlMessagesIndividually(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
	}{
		{name: "MLD query", messageType: layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage},
		{name: "MLD report", messageType: layers.ICMPv6TypeMLDv1MulticastListenerReportMessage},
		{name: "MLD done", messageType: layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage},
		{name: "router solicitation", messageType: layers.ICMPv6TypeRouterSolicitation},
		{name: "router advertisement", messageType: layers.ICMPv6TypeRouterAdvertisement},
		{name: "neighbor solicitation", messageType: layers.ICMPv6TypeNeighborSolicitation},
		{name: "neighbor advertisement", messageType: layers.ICMPv6TypeNeighborAdvertisement},
		{name: "redirect", messageType: layers.ICMPv6TypeRedirect},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv6ICMPPacket(t, test.messageType, 0, bytes.Repeat([]byte{0}, 8))
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			requireDropped(t, result, err)
		})
	}
}

// RFC 4443 Sections 3.1 through 3.4, as used by RFC 7915 Section 5.2: invalid ICMPv6 error codes are rejected or silently dropped where specified.
func TestTranslateRejectsInvalidICMPv6Codes(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
	}{
		{name: "Destination Unreachable", messageType: layers.ICMPv6TypeDestinationUnreachable},
		{name: "Packet Too Big", messageType: layers.ICMPv6TypePacketTooBig},
		{name: "Time Exceeded", messageType: layers.ICMPv6TypeTimeExceeded},
		{name: "Parameter Problem", messageType: layers.ICMPv6TypeParameterProblem},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv6ICMPPacket(t, test.messageType, 255, bytes.Repeat([]byte{0}, 8))
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			if test.messageType == layers.ICMPv6TypeDestinationUnreachable || test.messageType == layers.ICMPv6TypeParameterProblem {
				requireDropped(t, result, err)
				return
			}
			requireRejected(t, result, err)
		})
	}
}
