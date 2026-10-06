package siit_test

import (
	"bytes"
	"fmt"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Section 4.2: the remaining ICMPv4 types and Destination Unreachable codes are silently dropped.
func TestTranslateDropsRemainingICMPv4ErrorCodes(t *testing.T) {
	inner := ipv4TCPPacket(t, defaultTTL).Data()
	for _, test := range []struct {
		name     string
		icmpType uint8
		code     uint8
	}{
		{name: "unreachable code 16", icmpType: layers.ICMPv4TypeDestinationUnreachable, code: 16},
		{name: "unreachable code 255", icmpType: layers.ICMPv4TypeDestinationUnreachable, code: 255},
		{name: "redirect", icmpType: layers.ICMPv4TypeRedirect, code: 1},
		{name: "source quench", icmpType: 4, code: 0},
		{name: "alternate host address", icmpType: 6, code: 0},
		{name: "parameter problem code 3", icmpType: layers.ICMPv4TypeParameterProblem, code: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := testTranslator().TranslateIPv4(ipv4ICMPPacket(t, test.icmpType, test.code, inner), siit.TranslationOverrides{})
			requireDropped(t, result, err)
		})
	}
}

// RFC 7915 Section 5.2: unknown ICMPv6 informational and error messages are silently dropped.
func TestTranslateDropsUnknownICMPv6Messages(t *testing.T) {
	for _, messageType := range []uint8{5, 100, 127, 144, 200, 255} {
		t.Run(fmt.Sprintf("type %d", messageType), func(t *testing.T) {
			result, err := testTranslator().TranslateIPv6(ipv6ICMPPacket(t, messageType, 0, make([]byte, 8)), siit.TranslationOverrides{})
			requireDropped(t, result, err)
		})
	}
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
		{name: "unassigned type 0x22", messageType: 0x22},
		{name: "unknown", messageType: 255},
		{name: "redirect", messageType: layers.ICMPv4TypeRedirect},
		{name: "alternate host address", messageType: 6},
		{name: "source quench", messageType: 4},
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

// RFC 7915 Sections 4.2 and 5.2: unsupported ICMP error codes are silently dropped.
func TestTranslateDropsUnsupportedICMPErrorCodes(t *testing.T) {
	ipv4 := ipv4ICMPPacket(t, layers.ICMPv4TypeParameterProblem, 1, make([]byte, 8))
	result, err := testTranslator().TranslateIPv4(ipv4, siit.TranslationOverrides{})
	requireDropped(t, result, err)

	ipv6 := ipv6ICMPPacket(t, layers.ICMPv6TypeParameterProblem, 2, make([]byte, 8))
	result, err = testTranslator().TranslateIPv6(ipv6, siit.TranslationOverrides{})
	requireDropped(t, result, err)
}
