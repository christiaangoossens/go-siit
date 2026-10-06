package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.3 and 5.3: the quoted packet's TTL or Hop Limit is unchanged in either translation direction.
func TestTranslateIPv4ICMPErrorPreservesQuotedTTL(t *testing.T) {
	inner := ipv4TCPPacketWithAddresses(t, 37, ipv4Source, ipv4Dest)
	input := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, inner.Data())
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	outer := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	quoted := icmpv6ErrorQuote(t, outer)
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

// RFC 7915 Sections 4.3 and 5.3: translating an ICMP error must not decrement the quoted packet's TTL or Hop Limit.
func TestTranslateICMPErrorPreservesQuotedHopLimit(t *testing.T) {
	// The router-address fallback of RFC 6791 applies only to the outer source of an ICMPv6 error, never to
	// addresses inside the quoted packet, so only mappable quoted sources are tested.
	for _, test := range []struct {
		name        string
		innerSource net.IP
		wantSource  net.IP
	}{
		{name: "mapped source", innerSource: ipv4TranslatedDest, wantSource: ipv4Dest},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := ipv6TCPPacketWithAddresses(t, 37, test.innerSource, ipv6Dest)
			input := ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, inner.Data())
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			outer := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			icmp, ok := outer.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok {
				t.Fatalf("missing translated ICMPv4 layer: %v", outer.ErrorLayer())
			}
			quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
			ip, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ip.TTL != 37 || !ip.SrcIP.Equal(test.wantSource) || !ip.DstIP.Equal(ipv6TranslatedDest) || ip.Protocol != layers.IPProtocolTCP {
				t.Fatalf("quoted IPv6 header was not translated as expected: %+v", ip)
			}
			tcp, ok := quoted.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok || !bytes.Equal(tcp.Payload, []byte("hello")) {
				t.Fatalf("quoted IPv6 transport data was not translated: %v", quoted.ErrorLayer())
			}
			if outerIP := outer.Layer(layers.LayerTypeIPv4).(*layers.IPv4); outerIP.Length != uint16(len(result)) {
				t.Fatalf("translated IPv6 ICMP error has incorrect IPv4 total length: %d", outerIP.Length)
			}
		})
	}
}

// RFC 7915 Sections 4.3 and 5.3: an ICMP error containing a nested IP packet must be dropped.
func TestTranslateDropsNestedICMPError(t *testing.T) {
	inner := ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, ipv6TCPPacket(t, defaultTTL).Data())
	outer := ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, inner.Data())
	result, err := testTranslator().TranslateIPv6(outer, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("nested IPv6 ICMP error was translated: err=%v", err)
	}
}

// RFC 7915 Section 4.3: an IPv4 ICMP error containing a nested IP packet must be dropped.
func TestTranslateDropsNestedIPv4ICMPError(t *testing.T) {
	inner := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, ipv4TCPPacket(t, defaultTTL).Data())
	outer := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, inner.Data())
	result, err := testTranslator().TranslateIPv4(outer, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("nested IPv4 ICMP error was translated: err=%v", err)
	}
}

// RFC 7915 Sections 4.3 and 5.3: an ICMP error with an invalid quoted IP packet cannot be translated.
func TestTranslateDropsMalformedQuotedIPPacket(t *testing.T) {
	tests := []struct {
		name      string
		translate func(gopacket.Packet) (siit.TranslatedPacket, error)
		input     gopacket.Packet
	}{
		{
			name:  "IPv4 outer and quote",
			input: ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 3, []byte{0x45, 0, 0, 20}),
			translate: func(input gopacket.Packet) (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			},
		},
		{
			name:  "IPv6 outer and quote",
			input: ipv6ICMPPacket(t, layers.ICMPv6TypeDestinationUnreachable, 4, []byte{0x60, 0, 0, 0}),
			translate: func(input gopacket.Packet) (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(test.input)
			if result.Packet != nil {
				t.Fatalf("malformed quoted packet was translated: err=%v", err)
			}
		})
	}
}

// RFC 7915 Section 4.3: the quoted packet is translated like a normal packet "except the TTL value of the
// inner IPv4/IPv6 packet", so a quoted TTL of 1 (as produced by traceroute) must not expire it.
func TestTranslateIPv4ICMPErrorQuotingExpiringPacket(t *testing.T) {
	for _, test := range []struct {
		name     string
		icmpType uint8
		code     uint8
	}{
		{name: "port unreachable", icmpType: layers.ICMPv4TypeDestinationUnreachable, code: 3},
		{name: "time exceeded", icmpType: layers.ICMPv4TypeTimeExceeded, code: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := ipv4TCPPacketWithAddresses(t, 1, ipv4Source, ipv4Dest).Data()
			input := ipv4ICMPPacketWithRest(t, test.icmpType, test.code, 0, 0, inner)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			quote := icmpv6ErrorQuote(t, gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default))
			quotedIP, ok := quote.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || quotedIP.HopLimit != 1 {
				t.Fatalf("quoted Hop Limit must stay 1: %+v", quotedIP)
			}
		})
	}
}

// RFC 7915 Section 5.3: same rule for ICMPv6 errors quoting a packet whose Hop Limit is 1.
func TestTranslateIPv6ICMPErrorQuotingExpiringPacket(t *testing.T) {
	inner := ipv6TCPPacketWithAddresses(t, 1, ipv6Dest, ipv6Source).Data()
	input := ipv6ICMPErrorPacket(t, ipv6Source, ipv6Dest, icmpv6DestUnreachable, 4, zeroRestHeader(), inner)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	icmp := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	quotedIP, ok := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || quotedIP.TTL != 1 {
		t.Fatalf("quoted TTL must stay 1: %+v", quotedIP)
	}
}

// RFC 792 only requires an ICMP error to quote the IP header plus the first 8 octets of the original datagram,
// which is less than a TCP header. RFC 7915 Sections 4.3 and 5.3 still require translating the quoted header.
func TestTranslateICMPErrorWithMinimalQuote(t *testing.T) {
	t.Run("IPv4 to IPv6", func(t *testing.T) {
		original := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, ipv4Dest).Data()
		quoted := original[:ipv4HeaderLength+8]
		input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeDestinationUnreachable, 3, 0, 0, quoted)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
		})
		icmp := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		quote := icmp.Payload[icmpErrorRestHeaderSize:]
		if len(quote) != ipv6HeaderLength+8 || quote[6] != byte(layers.IPProtocolTCP) ||
			!bytes.Equal(quote[8:24], ipv4TranslatedSource) || !bytes.Equal(quote[24:40], ipv4TranslatedDest) ||
			!bytes.Equal(quote[40:], quoted[ipv4HeaderLength:]) {
			t.Fatalf("quoted IPv4 header + 8 octets was not translated to IPv6 header + 8 octets: %x", quote)
		}
	})
	t.Run("IPv6 to IPv4", func(t *testing.T) {
		original := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Dest, ipv6Source).Data()
		quoted := original[:ipv6HeaderLength+8]
		input := ipv6ICMPErrorPacket(t, ipv6Source, ipv6Dest, icmpv6DestUnreachable, 4, zeroRestHeader(), quoted)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		})
		icmp := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		quote := icmp.Payload
		if len(quote) != ipv4HeaderLength+8 || quote[9] != byte(layers.IPProtocolTCP) ||
			!bytes.Equal(quote[12:16], ipv4Source) || !bytes.Equal(quote[16:20], ipv6TranslatedSource.To4()) ||
			!bytes.Equal(quote[20:], quoted[ipv6HeaderLength:]) {
			t.Fatalf("quoted IPv6 header + 8 octets was not translated to IPv4 header + 8 octets: %x", quote)
		}
	})
}

// RFC 7915 Sections 4.1 and 5.1: the Time Exceeded message the library generates for an expired IPv4 packet is
// addressed to the translated IPv4 sender, so feeding it back through TranslateIPv6 must produce a deliverable
// ICMPv4 Time Exceeded for that sender.
func TestGeneratedTimeExceededCanBeTranslatedBack(t *testing.T) {
	generated, err := testTranslator().TranslateIPv4(ipv4TCPPacket(t, 1), siit.TranslationOverrides{})
	if !errors.Is(err, siit.ErrTimeExceeded) || generated.Packet == nil {
		t.Fatalf("expired packet did not generate Time Exceeded: err=%v", err)
	}
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(gopacket.NewPacket(generated.Packet, layers.LayerTypeIPv6, gopacket.Default), siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmp, ok2 := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || !ok2 || !ip.DstIP.Equal(ipv4Source) || !ip.SrcIP.Equal(ipv4RouterAddress) || icmp.TypeCode != layers.CreateICMPv4TypeCode(icmpv4TimeExceeded, 0) {
		t.Fatalf("generated Time Exceeded was not translated into a deliverable ICMPv4 error: %v", packet.ErrorLayer())
	}
}

// RFC 7757 Section 3.2: every address in the headers, including those inside ICMP errors, is translated
// individually through the EAM table.
func TestTranslateICMPErrorsUseEAMForOuterAndQuotedAddresses(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
		{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::20/128"},
	})
	host1, host2 := netIP("2001:db8::10"), netIP("2001:db8::20")

	t.Run("IPv4 to IPv6", func(t *testing.T) {
		inner := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, ipv4Dest).Data()
		input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeDestinationUnreachable, 3, 0, 0, inner)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return translator.TranslateIPv4(input, siit.TranslationOverrides{})
		})
		packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
		outer := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !outer.SrcIP.Equal(host2) || !outer.DstIP.Equal(host1) {
			t.Fatalf("outer addresses %s -> %s, want %s -> %s", outer.SrcIP, outer.DstIP, host2, host1)
		}
		quoted, ok := icmpv6ErrorQuote(t, packet).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !ok || !quoted.SrcIP.Equal(host1) || !quoted.DstIP.Equal(host2) {
			t.Fatalf("quoted addresses were not EAM-translated: %+v", quoted)
		}
	})
	t.Run("IPv6 to IPv4", func(t *testing.T) {
		inner := ipv6TCPPacketWithAddresses(t, defaultTTL, host1, host2).Data()
		input := ipv6ICMPErrorPacket(t, host2, host1, icmpv6DestUnreachable, 4, zeroRestHeader(), inner)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return translator.TranslateIPv6(input, siit.TranslationOverrides{})
		})
		packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
		outer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !outer.SrcIP.Equal(ipv4Dest) || !outer.DstIP.Equal(ipv4Source) {
			t.Fatalf("outer addresses %s -> %s, want %s -> %s", outer.SrcIP, outer.DstIP, ipv4Dest, ipv4Source)
		}
		icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		quoted, ok := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || !quoted.SrcIP.Equal(ipv4Source) || !quoted.DstIP.Equal(ipv4Dest) {
			t.Fatalf("quoted addresses were not EAM-translated: %+v", quoted)
		}
	})
}

// RFC 7915 Section 4.2: with the translator limited to the minimum IPv6 MTU, a Fragmentation Needed error
// that reports no MTU (RFC 1191 plateau case) still yields a Packet Too Big of 1280, the lowest legal value.
func TestTranslateFragmentationNeededWithoutMTUReportsMinimumIPv6MTU(t *testing.T) {
	quoted := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, ipv4Dest).Data()
	input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeDestinationUnreachable, 4, 0, 0, quoted)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	icmp := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0) || binary.BigEndian.Uint32(icmp.Payload[:4]) != 1280 {
		t.Fatalf("unexpected Packet Too Big: %+v MTU=%d", icmp.TypeCode, binary.BigEndian.Uint32(icmp.Payload[:4]))
	}
}

// RFC 7915 Sections 5.2 and 5.3 with RFC 6791 Section 3: an ICMPv6 error from a native IPv6 router (no IPv4
// mapping) is translated, using the configured IPv4 router address as the IPv4 source. The destination is the
// translated IPv4 host and must still map normally.
func TestTranslateICMPv6ErrorFromUnmappableRouterUsesRouterAddress(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::2/128"}})
	quoted := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv4TranslatedSource, net.ParseIP("2001:db8::2")).Data()
	input := ipv6ICMPErrorPacket(t, net.ParseIP("2a00:1098:82:72::1"), ipv4TranslatedSource, icmpv6DestUnreachable, 0, zeroRestHeader(), quoted)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv6(input, siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatalf("missing translated IPv4 layer: %v", packet.ErrorLayer())
	}
	if !ip.SrcIP.Equal(ipv4RouterAddress) || !ip.DstIP.Equal(ipv4Source) {
		t.Fatalf("got IPv4 error addresses %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, ipv4RouterAddress, ipv4Source)
	}
	translated, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || translated.TypeCode != layers.CreateICMPv4TypeCode(icmpv4DestUnreachable, 1) {
		t.Fatalf("got ICMPv4 error %#v, want destination unreachable/host unreachable", translated)
	}
	quote := gopacket.NewPacket(translated.Payload, layers.LayerTypeIPv4, gopacket.Default)
	quotedIP, ok := quote.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || !quotedIP.SrcIP.Equal(ipv4Source) || !quotedIP.DstIP.Equal(ipv4Dest) {
		t.Fatalf("quoted packet was not translated with the mapped addresses: %v", quote.ErrorLayer())
	}
}

// RFC 7915 Sections 5.1 and 5.6: only the source may fall back to the router address; an ICMPv6 error whose
// destination has no IPv4 mapping is not addressed to the IPv4 domain and must not be translated.
func TestTranslateICMPv6ErrorToUnmappableDestinationIsNotTranslated(t *testing.T) {
	quoted := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Unmappable, ipv6Dest).Data()
	input := ipv6ICMPErrorPacket(t, net.ParseIP("2a00:1098:82:72::1"), net.ParseIP("2a10:3781:56d5:8::e7"), icmpv6DestUnreachable, 0, zeroRestHeader(), quoted)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("ICMPv6 error to an unmappable destination was translated: err=%v", err)
	}
}

// RFC 7915 Sections 4.3 and 4.2 with RFC 4443: the ICMPv6 error carries a four-byte unused word before the
// translated quoted packet; the quoted packet's TTL is copied unchanged.
func TestTranslateIPv4ICMPErrorPreservesQuotedEcho(t *testing.T) {
	inner := ipv4ICMPPacket(t, echoRequest, 0, []byte("icmp")).Data()
	input := ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 1, inner)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	quoted := icmpv6ErrorQuote(t, packet)
	quotedIP, ok := quoted.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || quotedIP.HopLimit != defaultTTL || !quotedIP.SrcIP.Equal(ipv4TranslatedSource) || !quotedIP.DstIP.Equal(ipv4TranslatedDest) || quotedIP.NextHeader != layers.IPProtocolICMPv6 {
		t.Fatalf("quoted IPv4 packet was not preserved during translation: %+v", quotedIP)
	}
	quotedICMP, ok := quoted.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || quotedICMP.TypeCode.Type() != layers.ICMPv6TypeEchoRequest || !bytes.Equal(quotedICMP.Payload, []byte{0, 0, 0, 0, 'i', 'c', 'm', 'p'}) {
		t.Fatalf("quoted ICMP Echo Request changed: %+v", quotedICMP)
	}
}

// RFC 7915 Sections 4.2 and 7: IPv4 Fragmentation Needed becomes ICMPv6 Packet Too Big with an IPv6-sized MTU.
func TestTranslateIPv4FragmentationNeededPreservesMinimumMTU(t *testing.T) {
	inner := ipv4TCPPacket(t, defaultTTL).Data()
	outer := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4,
		SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	fragmentationNeeded := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 4),
		Seq:      1200,
	}
	input := gopacket.NewPacket(serializeTestPacket(t, outer, fragmentationNeeded, gopacket.Payload(inner)), layers.LayerTypeIPv4, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		t.Fatalf("missing translated IPv6 layer: %v", packet.ErrorLayer())
	}
	translated, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || translated.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0) {
		t.Fatalf("unexpected translated ICMPv6 Packet Too Big: %+v", translated)
	}
	if got := binary.BigEndian.Uint32(translated.Payload[:4]); got != 1280 {
		t.Fatalf("translated MTU is %d, want 1280", got)
	}
	if translated.Checksum != recalculatedICMPv6Checksum(t, ip, translated) {
		t.Fatalf("translated ICMPv6 checksum is invalid: %#x", translated.Checksum)
	}
}

func TestTranslateIPv4FragmentationNeededAddsHeaderSizeToMTU(t *testing.T) {
	_, nat64Net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}
	translator, err := siit.NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}

	outer := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4,
		SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	fragmentationNeeded := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 4),
		Seq:      1400,
	}
	input := gopacket.NewPacket(serializeTestPacket(t, outer, fragmentationNeeded, gopacket.Payload(ipv4TCPPacket(t, defaultTTL).Data())), layers.LayerTypeIPv4, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(input, siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	translated := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if got := binary.BigEndian.Uint32(translated.Payload[:4]); got != 1420 {
		t.Fatalf("translated MTU is %d, want 1420", got)
	}
}

func TestTranslateIPv6ICMPErrorPreservesQuotedEcho(t *testing.T) {
	outer := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv4TranslatedSource,
	}
	outerICMP := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 0)}
	if err := outerICMP.SetNetworkLayerForChecksum(outer); err != nil {
		t.Fatal(err)
	}
	innerIP := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL,
		SrcIP: ipv4TranslatedSource, DstIP: ipv4TranslatedDest,
	}
	innerICMP := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	if err := innerICMP.SetNetworkLayerForChecksum(innerIP); err != nil {
		t.Fatal(err)
	}
	inner := serializeTestPacket(t, innerIP, innerICMP, gopacket.Payload([]byte{0, 0, 0, 0, 'i', 'c', 'm', 'p'}))
	input := gopacket.NewPacket(serializeTestPacket(t, outer, outerICMP, gopacket.Payload(append(zeroRestHeader(), inner...))), layers.LayerTypeIPv6, gopacket.Default)
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::2/128"},
	})
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv6(input, siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	translated, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		t.Fatalf("missing translated ICMPv4 layer: %v", packet.ErrorLayer())
	}
	quoted := gopacket.NewPacket(translated.Payload, layers.LayerTypeIPv4, gopacket.Default)
	quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || quotedIP.TTL != defaultTTL || !quotedIP.SrcIP.Equal(ipv4Source) || !quotedIP.DstIP.Equal(ipv4Dest) || quotedIP.Protocol != layers.IPProtocolICMPv4 {
		t.Fatalf("quoted IPv6 packet was not preserved during translation: %+v", quotedIP)
	}
	quotedICMP, ok := quoted.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || quotedICMP.TypeCode.Type() != echoRequest || quotedICMP.Id != 0 || quotedICMP.Seq != 0 || !bytes.Equal(quotedICMP.Payload, []byte("icmp")) {
		t.Fatalf("quoted ICMP Echo Request changed: %+v", quotedICMP)
	}
}

func TestTranslateIPv6ICMPErrorUsesMappedOuterDestinationInQuote(t *testing.T) {
	outerDestination := net.ParseIP("2001:db8::2")
	outer := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: outerDestination,
	}
	outerICMP := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 0)}
	if err := outerICMP.SetNetworkLayerForChecksum(outer); err != nil {
		t.Fatal(err)
	}
	innerIP := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL,
		SrcIP: outerDestination, DstIP: ipv4TranslatedDest,
	}
	innerICMP := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	if err := innerICMP.SetNetworkLayerForChecksum(innerIP); err != nil {
		t.Fatal(err)
	}
	inner := serializeTestPacket(t, innerIP, innerICMP, gopacket.Payload([]byte{0, 0, 0, 0, 'i', 'c', 'm', 'p'}))
	input := gopacket.NewPacket(serializeTestPacket(t, outer, outerICMP, gopacket.Payload(append(zeroRestHeader(), inner...))), layers.LayerTypeIPv6, gopacket.Default)
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::2/128"},
	})
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv6(input, siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	translated, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		t.Fatalf("missing translated ICMPv4 layer: %v", packet.ErrorLayer())
	}
	quoted := gopacket.NewPacket(translated.Payload, layers.LayerTypeIPv4, gopacket.Default)
	quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || !quotedIP.SrcIP.Equal(ipv4Source) {
		t.Fatalf("quoted source is %s, want %s", quotedIP.SrcIP, ipv4Source)
	}
}

func TestTranslateIPv6TimeExceededUsesEAMSourceMapping(t *testing.T) {
	eamSource := net.ParseIP("2001:db8::2")
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::2/128"},
	})
	input := ipv6TCPPacketWithAddresses(t, 1, eamSource, ipv4TranslatedDest)
	result, err := translator.TranslateIPv6(input, siit.TranslationOverrides{})
	if !errors.Is(err, siit.ErrTimeExceeded) {
		t.Fatalf("got error %v, want ErrTimeExceeded", err)
	}

	packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || !ip.DstIP.Equal(ipv4Source) {
		t.Fatalf("generated error destination is %s, want %s", ip.DstIP, ipv4Source)
	}
	quoted := gopacket.NewPacket(packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4).Payload, layers.LayerTypeIPv4, gopacket.Default)
	quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || !quotedIP.SrcIP.Equal(ipv4Source) {
		t.Fatalf("quoted source is %s, want %s", quotedIP.SrcIP, ipv4Source)
	}
}

// RFC 7915 Sections 5.2 and 5.3: IPv6 Destination Unreachable and Time Exceeded codes map to ICMPv4 errors.
func TestTranslateICMPv6ErrorMappings(t *testing.T) {
	cases := []struct {
		name     string
		typeCode layers.ICMPv6TypeCode
		wantType uint8
		wantCode uint8
	}{
		{name: "no route", typeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 0), wantType: icmpv4DestUnreachable, wantCode: 1},
		{name: "administratively prohibited", typeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 1), wantType: icmpv4DestUnreachable, wantCode: 10},
		{name: "beyond source scope", typeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 2), wantType: icmpv4DestUnreachable, wantCode: 1},
		{name: "address unreachable", typeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 3), wantType: icmpv4DestUnreachable, wantCode: 1},
		{name: "port unreachable", typeCode: layers.CreateICMPv6TypeCode(icmpv6DestUnreachable, 4), wantType: icmpv4DestUnreachable, wantCode: 3},
		{name: "time exceeded", typeCode: layers.CreateICMPv6TypeCode(icmpv6TimeExceeded, 0), wantType: icmpv4TimeExceeded, wantCode: 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outer := &layers.IPv6{
				Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL,
				SrcIP: ipv6Source, DstIP: ipv6Dest,
			}
			icmp := &layers.ICMPv6{TypeCode: test.typeCode}
			if err := icmp.SetNetworkLayerForChecksum(outer); err != nil {
				t.Fatal(err)
			}
			inner := ipv6TCPPacket(t, defaultTTL)
			input := gopacket.NewPacket(serializeTestPacket(t, outer, icmp, gopacket.Payload(append(zeroRestHeader(), inner.Data()...))), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			translated, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok {
				t.Fatalf("missing translated ICMPv4 layer: %v", packet.ErrorLayer())
			}
			if translated.TypeCode.Type() != test.wantType || translated.TypeCode.Code() != test.wantCode {
				t.Fatalf("got ICMPv4 type/code %d/%d, want %d/%d", translated.TypeCode.Type(), translated.TypeCode.Code(), test.wantType, test.wantCode)
			}
			if translated.Checksum != recalculatedICMPv4Checksum(t, translated) {
				t.Fatalf("got invalid ICMPv4 checksum: %#x", translated.Checksum)
			}
		})
	}
}

// RFC 7915 Sections 5.2 and 7: Packet Too Big MTU values are reduced by the header-size difference.
func TestTranslateICMPv6PacketTooBigMTUBoundaries(t *testing.T) {
	for _, test := range []struct {
		name          string
		translatorMTU uint32
		mtu           uint32
		want          uint16
	}{
		{name: "minimum IPv6 MTU", translatorMTU: 1280, mtu: 1280, want: 1260},
		// The reported MTU can never exceed what the translator's own IPv6 side supports (IPv6 next hop MTU - 20).
		{name: "larger than the default IPv6 MTU", translatorMTU: 1280, mtu: 1500, want: 1260},
		{name: "configured MTU", translatorMTU: 1500, mtu: 1500, want: 1480},
		{name: "larger than the configured MTU", translatorMTU: 1500, mtu: 9000, want: 1480},
		{name: "smaller than the configured MTU", translatorMTU: 1500, mtu: 1400, want: 1380},
	} {
		t.Run(test.name, func(t *testing.T) {
			mtu := make([]byte, 4)
			binary.BigEndian.PutUint32(mtu, test.mtu)
			input := ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypePacketTooBig, 0, mtu, ipv6TCPPacket(t, defaultTTL).Data())
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translatorWithMTU(t, test.translatorMTU).TranslateIPv6(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 4) || icmp.Seq != test.want {
				t.Fatalf("got ICMPv4 Packet Too Big translation %#v, want MTU %d", icmp, test.want)
			}
			if icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
				t.Fatalf("translated Packet Too Big checksum is invalid: %#x", icmp.Checksum)
			}
		})
	}
}

// RFC 7915 Sections 4.2 and 4.3: required IPv4 error codes are translated and Host Precedence Violation is dropped.
func TestTranslateIPv4ICMPErrorMatrix(t *testing.T) {
	cases := []struct {
		name     string
		icmpType uint8
		code     uint8
		wantType uint8
		wantCode uint8
	}{
		{name: "network unreachable", icmpType: 3, code: 0, wantType: 1, wantCode: 0},
		{name: "host unreachable", icmpType: 3, code: 1, wantType: 1, wantCode: 0},
		{name: "protocol unreachable", icmpType: 3, code: 2, wantType: 4, wantCode: 1},
		{name: "port unreachable", icmpType: 3, code: 3, wantType: 1, wantCode: 4},
		{name: "fragmentation needed", icmpType: 3, code: 4, wantType: 2, wantCode: 0},
		{name: "source route failed", icmpType: 3, code: 5, wantType: 1, wantCode: 0},
		{name: "network unknown", icmpType: 3, code: 6, wantType: 1, wantCode: 0},
		{name: "host unknown", icmpType: 3, code: 7, wantType: 1, wantCode: 0},
		{name: "isolated", icmpType: 3, code: 8, wantType: 1, wantCode: 0},
		{name: "network administratively prohibited", icmpType: 3, code: 9, wantType: 1, wantCode: 1},
		{name: "host administratively prohibited", icmpType: 3, code: 10, wantType: 1, wantCode: 1},
		{name: "network unreachable for service", icmpType: 3, code: 11, wantType: 1, wantCode: 0},
		{name: "host unreachable for service", icmpType: 3, code: 12, wantType: 1, wantCode: 0},
		{name: "communication administratively prohibited", icmpType: 3, code: 13, wantType: 1, wantCode: 1},
		{name: "host precedence violation", icmpType: 3, code: 14},
		{name: "precedence cutoff", icmpType: 3, code: 15, wantType: 1, wantCode: 1},
		{name: "time exceeded", icmpType: 11, code: 0, wantType: 3, wantCode: 0},
		{name: "time exceeded in transit", icmpType: 11, code: 1, wantType: 3, wantCode: 1},
		{name: "parameter problem", icmpType: 12, code: 0, wantType: 4, wantCode: 0},
		{name: "parameter problem bad length", icmpType: 12, code: 2, wantType: 4, wantCode: 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outer := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
			icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(test.icmpType, test.code)}
			inner := ipv4TCPPacket(t, defaultTTL)
			input := gopacket.NewPacket(serializeTestPacket(t, outer, icmp, gopacket.Payload(inner.Data())), layers.LayerTypeIPv4, gopacket.Default)
			if test.icmpType == icmpv4DestUnreachable && test.code == 14 {
				result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
				if err != nil || result.Packet != nil {
					t.Fatalf("host precedence violation was not silently dropped: result length=%d err=%v", len(result.Packet), err)
				}
				return
			}
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			translated, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok {
				t.Fatalf("missing translated ICMPv6 layer: %v", packet.ErrorLayer())
			}
			if translated.TypeCode.Type() != test.wantType || translated.TypeCode.Code() != test.wantCode {
				t.Fatalf("got ICMPv6 type/code %d/%d, want %d/%d", translated.TypeCode.Type(), translated.TypeCode.Code(), test.wantType, test.wantCode)
			}
			if translated.Checksum != recalculatedICMPv6Checksum(t, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), translated) {
				t.Fatalf("got invalid ICMPv6 checksum: %#x", translated.Checksum)
			}
		})
	}
}

// RFC 7915 Sections 5.2 and 5.3: IPv6 Packet Too Big and Parameter Problem require translation to ICMPv4.
func TestTranslateIPv6ICMPErrorMatrix(t *testing.T) {
	cases := []struct {
		name     string
		icmpType uint8
		code     uint8
		rest     []byte
		wantType uint8
		wantCode uint8
	}{
		// The type-specific word is the MTU for Packet Too Big and the pointer for Parameter Problem.
		{name: "packet too big", icmpType: 2, code: 0, rest: icmpPointer(1280), wantType: 3, wantCode: 4},
		{name: "time exceeded in transit", icmpType: 3, code: 1, rest: zeroRestHeader(), wantType: 11, wantCode: 1},
		{name: "parameter problem", icmpType: 4, code: 0, rest: icmpPointer(6), wantType: 12, wantCode: 0},
		{name: "unrecognized next header", icmpType: 4, code: 1, rest: icmpPointer(6), wantType: 3, wantCode: 2},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outer := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(test.icmpType, test.code)}
			if err := icmp.SetNetworkLayerForChecksum(outer); err != nil {
				t.Fatal(err)
			}
			inner := ipv6TCPPacket(t, defaultTTL)
			input := gopacket.NewPacket(serializeTestPacket(t, outer, icmp, gopacket.Payload(append(append([]byte{}, test.rest...), inner.Data()...))), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			translated, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok {
				t.Fatalf("missing translated ICMPv4 layer: %v", packet.ErrorLayer())
			}
			if translated.TypeCode.Type() != test.wantType || translated.TypeCode.Code() != test.wantCode {
				t.Fatalf("got ICMPv4 type/code %d/%d, want %d/%d", translated.TypeCode.Type(), translated.TypeCode.Code(), test.wantType, test.wantCode)
			}
			if translated.Checksum != recalculatedICMPv4Checksum(t, translated) {
				t.Fatalf("got invalid ICMPv4 checksum: %#x", translated.Checksum)
			}
		})
	}
}

// RFC 7915 Section 4.2: a Fragmentation Needed error with an MTU of zero (RFC 1191 plateau case) is translated
// to min(plateau + 20, IPv6 MTU); for a 1500-byte datagram the plateau is 1492, so a 1500-byte IPv6 MTU gives 1500.
func TestTranslateFragmentationNeededWithoutMTUUsesConfiguredMTU(t *testing.T) {
	original := ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0xab}, 1500-ipv4HeaderLength-20), nil).Data()
	input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeDestinationUnreachable, 4, 0, 0, original[:ipv4HeaderLength+20+8])
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translatorWithMTU(t, 1500).TranslateIPv4(input, siit.TranslationOverrides{})
	})
	icmp := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if got := binary.BigEndian.Uint32(icmp.Payload[:4]); icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0) || got != 1500 {
		t.Fatalf("unexpected Packet Too Big: %+v MTU=%d, want MTU 1500", icmp.TypeCode, got)
	}
}
