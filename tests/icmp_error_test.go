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

// quoteTTL is a TTL / Hop Limit other than 1 and 64, so a decrement of the quoted packet is noticed.
const quoteTTL = 37

func requireQuotedTCPv6(t *testing.T, quote gopacket.Packet, source, destination net.IP, hopLimit uint8) {
	t.Helper()
	ip, ok := quote.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok || !ip.SrcIP.Equal(source) || !ip.DstIP.Equal(destination) || ip.HopLimit != hopLimit || ip.NextHeader != layers.IPProtocolTCP {
		t.Fatalf("quoted IPv6 header is %+v, want %s -> %s with Hop Limit %d", ip, source, destination, hopLimit)
	}
	tcp, ok := quote.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.Equal(tcp.Payload, segmentPayload) || tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) {
		t.Fatalf("quoted TCP segment was not translated with a valid checksum: %v", quote.ErrorLayer())
	}
}

func requireQuotedTCPv4(t *testing.T, quote gopacket.Packet, source, destination net.IP, ttl uint8) {
	t.Helper()
	ip, ok := quote.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || !ip.SrcIP.Equal(source) || !ip.DstIP.Equal(destination) || ip.TTL != ttl || ip.Protocol != layers.IPProtocolTCP {
		t.Fatalf("quoted IPv4 header is %+v, want %s -> %s with TTL %d", ip, source, destination, ttl)
	}
	tcp, ok := quote.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.Equal(tcp.Payload, segmentPayload) || tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) || ip.Checksum != ipv4HeaderChecksum(ip) {
		t.Fatalf("quoted TCP segment was not translated with valid checksums: %v", quote.ErrorLayer())
	}
}

// RFC 7915 Sections 4.2 and 4.3 (MUST): every ICMPv4 error type and code is either translated as specified or
// silently dropped, and the quoted packet is translated too, without decrementing its TTL.
// Covered: Destination Unreachable codes 0-15 and 16, 255; Time Exceeded; Parameter Problem codes 0-3. Source Quench,
// Redirect, Alternate Host, Router, Timestamp, Information, Address Mask and unknown types have no ICMPv6
// equivalent and are dropped. Outer and quoted addresses, the quoted TTL and the quoted TCP checksum are checked.
func TestTranslateICMPv4Messages(t *testing.T) {
	const drop = 255
	tests := []struct {
		name     string
		icmpType uint8
		code     uint8
		wantType uint8 // drop: silently dropped
		wantCode uint8
	}{
		{name: "net unreachable", icmpType: 3, code: 0, wantType: 1, wantCode: 0},
		{name: "host unreachable", icmpType: 3, code: 1, wantType: 1, wantCode: 0},
		{name: "protocol unreachable", icmpType: 3, code: 2, wantType: 4, wantCode: 1},
		{name: "port unreachable", icmpType: 3, code: 3, wantType: 1, wantCode: 4},
		{name: "fragmentation needed", icmpType: 3, code: 4, wantType: 2, wantCode: 0},
		{name: "source route failed", icmpType: 3, code: 5, wantType: 1, wantCode: 0},
		{name: "destination network unknown", icmpType: 3, code: 6, wantType: 1, wantCode: 0},
		{name: "destination host unknown", icmpType: 3, code: 7, wantType: 1, wantCode: 0},
		{name: "source host isolated", icmpType: 3, code: 8, wantType: 1, wantCode: 0},
		{name: "network administratively prohibited", icmpType: 3, code: 9, wantType: 1, wantCode: 1},
		{name: "host administratively prohibited", icmpType: 3, code: 10, wantType: 1, wantCode: 1},
		{name: "network unreachable for TOS", icmpType: 3, code: 11, wantType: 1, wantCode: 0},
		{name: "host unreachable for TOS", icmpType: 3, code: 12, wantType: 1, wantCode: 0},
		{name: "communication administratively prohibited", icmpType: 3, code: 13, wantType: 1, wantCode: 1},
		{name: "host precedence violation", icmpType: 3, code: 14, wantType: drop},
		{name: "precedence cutoff in effect", icmpType: 3, code: 15, wantType: 1, wantCode: 1},
		{name: "unreachable code 16", icmpType: 3, code: 16, wantType: drop},
		{name: "unreachable code 255", icmpType: 3, code: 255, wantType: drop},
		{name: "time exceeded in transit", icmpType: 11, code: 0, wantType: 3, wantCode: 0},
		{name: "time exceeded in reassembly", icmpType: 11, code: 1, wantType: 3, wantCode: 1},
		{name: "parameter problem pointer", icmpType: 12, code: 0, wantType: 4, wantCode: 0},
		{name: "parameter problem bad length", icmpType: 12, code: 2, wantType: 4, wantCode: 0},
		{name: "parameter problem missing option", icmpType: 12, code: 1, wantType: drop},
		{name: "parameter problem code 3", icmpType: 12, code: 3, wantType: drop},
		{name: "source quench", icmpType: 4, code: 0, wantType: drop},
		{name: "redirect for network", icmpType: 5, code: 0, wantType: drop},
		{name: "redirect for host", icmpType: 5, code: 1, wantType: drop},
		{name: "alternate host address", icmpType: 6, code: 0, wantType: drop},
		{name: "router advertisement", icmpType: 9, code: 0, wantType: drop},
		{name: "router solicitation", icmpType: 10, code: 0, wantType: drop},
		{name: "timestamp request", icmpType: 13, code: 0, wantType: drop},
		{name: "timestamp reply", icmpType: 14, code: 0, wantType: drop},
		{name: "information request", icmpType: 15, code: 0, wantType: drop},
		{name: "information reply", icmpType: 16, code: 0, wantType: drop},
		{name: "address mask request", icmpType: 17, code: 0, wantType: drop},
		{name: "address mask reply", icmpType: 18, code: 0, wantType: drop},
		{name: "unassigned type 34", icmpType: 34, code: 0, wantType: drop},
		{name: "unknown type 255", icmpType: 255, code: 0, wantType: drop},
	}
	quote := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, quoteTTL).Data()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ipv4ICMPPacket(t, test.icmpType, test.code, quote)
			if test.wantType == drop {
				result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
				requireDropped(t, result, err)
				return
			}
			result := translateToICMPv6(t, testTranslator(), input)
			if result.icmp.TypeCode != layers.CreateICMPv6TypeCode(test.wantType, test.wantCode) {
				t.Fatalf("got ICMPv6 type/code %v, want %d/%d", result.icmp.TypeCode, test.wantType, test.wantCode)
			}
			// The error travels back to ipv4Source; the quoted packet is translated and keeps its TTL.
			if !result.ip.SrcIP.Equal(ipv4TranslatedDest) || !result.ip.DstIP.Equal(ipv4TranslatedSource) {
				t.Fatalf("outer addresses %s -> %s", result.ip.SrcIP, result.ip.DstIP)
			}
			requireQuotedTCPv6(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest, quoteTTL)
		})
	}
}

// RFC 7915 Sections 5.2 and 5.3 (MUST), with RFC 4443 Sections 3.1-3.4: every ICMPv6 error type and code is either
// translated as specified or silently dropped, and the quoted packet is translated too, without decrementing its
// Hop Limit. Packet Too Big ignores its Code (RFC 4443 Section 3.2: "Set to 0 (zero) by the originator and ignored by the
// receiver"); the rows "packet too big with code 1 / 255" are regression guards, as such a message used to be rejected.
// MLD, Neighbor Discovery, Redirect and unknown types have no ICMPv4 equivalent and are dropped.
func TestTranslateICMPv6Messages(t *testing.T) {
	const drop = 255
	tests := []struct {
		name     string
		icmpType uint8
		code     uint8
		rest     []byte
		wantType uint8
		wantCode uint8
	}{
		{name: "no route to destination", icmpType: 1, code: 0, wantType: 3, wantCode: 1},
		{name: "administratively prohibited", icmpType: 1, code: 1, wantType: 3, wantCode: 10},
		{name: "beyond scope of source address", icmpType: 1, code: 2, wantType: 3, wantCode: 1},
		{name: "address unreachable", icmpType: 1, code: 3, wantType: 3, wantCode: 1},
		{name: "port unreachable", icmpType: 1, code: 4, wantType: 3, wantCode: 3},
		{name: "source address failed policy", icmpType: 1, code: 5, wantType: drop},
		{name: "reject route", icmpType: 1, code: 6, wantType: drop},
		{name: "unreachable code 255", icmpType: 1, code: 255, wantType: drop},
		{name: "packet too big", icmpType: 2, code: 0, rest: icmpPointer(1280), wantType: 3, wantCode: 4},
		{name: "packet too big with code 1", icmpType: 2, code: 1, rest: icmpPointer(1280), wantType: 3, wantCode: 4},
		{name: "packet too big with code 255", icmpType: 2, code: 255, rest: icmpPointer(1280), wantType: 3, wantCode: 4},
		{name: "hop limit exceeded in transit", icmpType: 3, code: 0, wantType: 11, wantCode: 0},
		{name: "fragment reassembly time exceeded", icmpType: 3, code: 1, wantType: 11, wantCode: 1},
		{name: "erroneous header field", icmpType: 4, code: 0, rest: icmpPointer(6), wantType: 12, wantCode: 0},
		{name: "unrecognized next header", icmpType: 4, code: 1, rest: icmpPointer(40), wantType: 3, wantCode: 2},
		{name: "unrecognized option", icmpType: 4, code: 2, rest: icmpPointer(40), wantType: drop},
		{name: "parameter problem code 3", icmpType: 4, code: 3, rest: icmpPointer(40), wantType: drop},
		{name: "parameter problem code 255", icmpType: 4, code: 255, rest: icmpPointer(40), wantType: drop},
		{name: "unassigned error type 5", icmpType: 5, wantType: drop},
		{name: "private experimentation error type 100", icmpType: 100, wantType: drop},
		{name: "extension error type 127", icmpType: 127, wantType: drop},
		{name: "MLD query", icmpType: layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage, wantType: drop},
		{name: "MLD report", icmpType: layers.ICMPv6TypeMLDv1MulticastListenerReportMessage, wantType: drop},
		{name: "MLD done", icmpType: layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage, wantType: drop},
		{name: "router solicitation", icmpType: layers.ICMPv6TypeRouterSolicitation, wantType: drop},
		{name: "router advertisement", icmpType: layers.ICMPv6TypeRouterAdvertisement, wantType: drop},
		{name: "neighbor solicitation", icmpType: layers.ICMPv6TypeNeighborSolicitation, wantType: drop},
		{name: "neighbor advertisement", icmpType: layers.ICMPv6TypeNeighborAdvertisement, wantType: drop},
		{name: "redirect", icmpType: layers.ICMPv6TypeRedirect, wantType: drop},
		{name: "unassigned informational type 144", icmpType: 144, wantType: drop},
		{name: "unknown type 200", icmpType: 200, wantType: drop},
		{name: "unknown type 255", icmpType: 255, wantType: drop},
	}
	quote := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, quoteTTL).Data()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rest := test.rest
			if rest == nil {
				rest = zeroRestHeader()
			}
			input := ipv6ICMPPacketWithRestHeader(t, test.icmpType, test.code, rest, quote)
			if test.wantType == drop {
				result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
				requireDropped(t, result, err)
				return
			}
			result := translateToICMPv4(t, testTranslator(), input)
			if result.icmp.TypeCode != layers.CreateICMPv4TypeCode(test.wantType, test.wantCode) {
				t.Fatalf("got ICMPv4 type/code %v, want %d/%d", result.icmp.TypeCode, test.wantType, test.wantCode)
			}
			if !result.ip.SrcIP.Equal(ipv4Source) || !result.ip.DstIP.Equal(ipv6TranslatedSource) {
				t.Fatalf("outer addresses %s -> %s", result.ip.SrcIP, result.ip.DstIP)
			}
			requireQuotedTCPv4(t, result.quote(), ipv6TranslatedSource, ipv4Source, quoteTTL)
		})
	}
}

// RFC 7915 Sections 4.3 and 5.3 (MUST): the TTL / Hop Limit of the quoted packet is not decremented and does not
// expire the translation, even when it is 1 (as in traceroute) or 0.
func TestTranslateICMPErrorWithExpiredQuotedPacket(t *testing.T) {
	for _, ttl := range []uint8{0, 1} {
		for _, messageType := range []uint8{3, 11} {
			t.Run(fmt.Sprintf("IPv4 type %d quoted TTL %d", messageType, ttl), func(t *testing.T) {
				quote := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, ttl).Data()
				result := translateToICMPv6(t, testTranslator(), ipv4ICMPPacket(t, messageType, 3, quote))
				requireQuotedTCPv6(t, result.quote(t), ipv4TranslatedSource, ipv4TranslatedDest, ttl)
			})
			t.Run(fmt.Sprintf("IPv6 type %d quoted Hop Limit %d", messageType, ttl), func(t *testing.T) {
				quote := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, ttl).Data()
				v6Type := map[uint8]uint8{3: layers.ICMPv6TypeDestinationUnreachable, 11: layers.ICMPv6TypeTimeExceeded}[messageType]
				result := translateToICMPv4(t, testTranslator(), ipv6ICMPPacket(t, v6Type, 0, quote))
				requireQuotedTCPv4(t, result.quote(), ipv6TranslatedSource, ipv6TranslatedDest, ttl)
			})
		}
	}
}

// ipv4FragmentPacket builds a TCP packet with explicit IPv4 fragmentation fields.
func ipv4FragmentPacket(t *testing.T, flags layers.IPv4Flag, offset uint16, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: quoteTTL, Id: 0x4321, Flags: flags, FragOffset: offset, Protocol: layers.IPProtocolTCP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

// RFC 7915 Sections 4.3 and 5.3 (MUST): the packet quoted in an ICMP error is translated like any packet, so IPv4
// options disappear, a fragment keeps its fragmentation state (as a Fragment header in the other family), IPv6
// extension headers are skipped, and a quote cut off after the first eight transport octets (RFC 792) still gets
// its header translated, with the Payload Length / Total Length describing the original packet.
func TestTranslateICMPErrorQuoteVariants(t *testing.T) {
	t.Run("IPv4 quote with options", func(t *testing.T) {
		quote := ipv4TCPPacketWithOptions(t, ipv4NOP, ipv4NOP, ipv4NOP, ipv4NOP).Data()
		result := translateToICMPv6(t, testTranslator(), ipv4ICMPPacket(t, 3, 3, quote))
		got := result.quote(t)
		ip, ok := got.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !ok || ip.NextHeader != layers.IPProtocolTCP || int(ip.Length) != len(quote)-24 {
			t.Fatalf("IPv4 options leaked into the quoted IPv6 packet: %+v", ip)
		}
	})
	t.Run("IPv4 first fragment", func(t *testing.T) {
		quote := ipv4FragmentPacket(t, layers.IPv4MoreFragments, 0, bytes.Repeat([]byte{7}, 32)).Data()
		got := translateToICMPv6(t, testTranslator(), ipv4ICMPPacket(t, 3, 3, quote)).quote(t)
		ip, ok := got.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !ok || ip.NextHeader != layers.IPProtocolIPv6Fragment || len(got.Data()) < ipv6HeaderLength+8 {
			t.Fatalf("quoted fragment lost its Fragment header: %+v", ip)
		}
		header := got.Data()[ipv6HeaderLength : ipv6HeaderLength+8]
		if header[0] != byte(layers.IPProtocolTCP) || header[2]&0xf8 != 0 || header[3]&1 != 1 || binary.BigEndian.Uint32(header[4:]) != 0x4321 {
			t.Fatalf("quoted Fragment header is wrong: %x", header)
		}
	})
	t.Run("IPv4 later fragment", func(t *testing.T) {
		quote := ipv4FragmentPacket(t, 0, 4, bytes.Repeat([]byte{7}, 32)).Data()
		got := translateToICMPv6(t, testTranslator(), ipv4ICMPPacket(t, 3, 3, quote)).quote(t)
		header := got.Data()[ipv6HeaderLength : ipv6HeaderLength+8]
		if got.Data()[6] != byte(layers.IPProtocolIPv6Fragment) || binary.BigEndian.Uint16(header[2:4])>>3 != 4 || header[3]&1 != 0 {
			t.Fatalf("quoted fragment offset was not preserved: %x", header)
		}
	})
	t.Run("IPv4 quote of a header and eight octets", func(t *testing.T) {
		original := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, quoteTTL).Data()
		quote := original[:ipv4HeaderLength+8]
		got := translateToICMPv6(t, testTranslator(), ipv4ICMPPacket(t, 3, 3, quote)).quote(t)
		data := got.Data()
		if len(data) != ipv6HeaderLength+8 || data[6] != byte(layers.IPProtocolTCP) || !bytes.Equal(data[8:24], ipv4TranslatedSource) ||
			!bytes.Equal(data[24:40], ipv4TranslatedDest) || !bytes.Equal(data[40:], quote[ipv4HeaderLength:]) {
			t.Fatalf("quoted header + 8 octets was not translated to IPv6 header + 8 octets: %x", data)
		}
		// The Payload Length keeps describing the original packet (RFC 8200 Section 3).
		if length := binary.BigEndian.Uint16(data[4:6]); int(length) != len(original)-ipv4HeaderLength {
			t.Fatalf("quoted Payload Length is %d, want %d", length, len(original)-ipv4HeaderLength)
		}
	})
	t.Run("IPv6 quote with extension headers", func(t *testing.T) {
		segment := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, quoteTTL).Data()[ipv6HeaderLength:]
		// A Routing header with Segments Left is fine inside a quote: the quoted packet is not routed.
		headers := cat(optionsHeader(layers.IPProtocolIPv6Routing), routingHeader(layers.IPProtocolTCP, 1))
		quote := ipv6PacketWithHeaders(t, layers.IPProtocolIPv6HopByHop, headers, segment).Data()
		got := translateToICMPv4(t, testTranslator(), ipv6ICMPPacket(t, 1, 4, quote)).quote()
		requireQuotedTCPv4(t, got, ipv6TranslatedSource, ipv6TranslatedDest, defaultTTL)
	})
	t.Run("IPv6 first fragment", func(t *testing.T) {
		fragment := []byte{byte(layers.IPProtocolTCP), 0, 0, 1, 0, 0, 0x43, 0x21}
		quote := ipv6PacketWithHeaders(t, layers.IPProtocolIPv6Fragment, fragment, bytes.Repeat([]byte{7}, 32)).Data()
		got := translateToICMPv4(t, testTranslator(), ipv6ICMPPacket(t, 1, 4, quote)).quote()
		ip, ok := got.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || ip.Protocol != layers.IPProtocolTCP || ip.Flags&layers.IPv4MoreFragments == 0 || ip.FragOffset != 0 || ip.Id != 0x4321 {
			t.Fatalf("quoted fragment lost its fragmentation state: %+v", ip)
		}
	})
	t.Run("IPv6 quote of a header and eight octets", func(t *testing.T) {
		original := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, quoteTTL).Data()
		quote := original[:ipv6HeaderLength+8]
		data := translateToICMPv4(t, testTranslator(), ipv6ICMPPacket(t, 1, 4, quote)).icmp.Payload
		if len(data) != ipv4HeaderLength+8 || data[9] != byte(layers.IPProtocolTCP) || !bytes.Equal(data[12:16], ipv6TranslatedSource.To4()) ||
			!bytes.Equal(data[16:20], ipv6TranslatedDest.To4()) || !bytes.Equal(data[20:], quote[ipv6HeaderLength:]) {
			t.Fatalf("quoted header + 8 octets was not translated to IPv4 header + 8 octets: %x", data)
		}
		if length := binary.BigEndian.Uint16(data[2:4]); int(length) != len(original)-ipv6HeaderLength+ipv4HeaderLength {
			t.Fatalf("quoted Total Length is %d, want %d", length, len(original)-ipv6HeaderLength+ipv4HeaderLength)
		}
	})
}

// RFC 7915 Sections 4.3 and 5.3 (MUST): an ICMP error that quotes an ICMP error, or whose quoted packet is not a
// valid IP packet, cannot be translated and is dropped. A quote that carries an illegal address is not
// translated either, because the translator would otherwise embed that address in the message it sends.
func TestTranslateDropsInvalidQuotes(t *testing.T) {
	nsp := translatorWithPrefix(t, "2001:db8:64::/96", nil)
	translateV4 := func(translator *siit.Translator, quote []byte) (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(ipv4ICMPPacket(t, 3, 3, quote), siit.TranslationOverrides{})
	}
	translateV6 := func(translator *siit.Translator, quote []byte) (siit.TranslatedPacket, error) {
		return translator.TranslateIPv6(ipv6ICMPPacket(t, 1, 4, quote), siit.TranslationOverrides{})
	}
	tests := []struct {
		name       string
		translator *siit.Translator
		translate  func(*siit.Translator, []byte) (siit.TranslatedPacket, error)
		quote      []byte
	}{
		{"IPv4 error quoting an ICMP error", testTranslator(), translateV4, ipv4ICMPPacket(t, 3, 3, ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()).Data()},
		{"IPv4 error quoting a time exceeded", testTranslator(), translateV4, ipv4ICMPPacket(t, 11, 0, ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()).Data()},
		{"IPv6 error quoting an ICMP error", testTranslator(), translateV6, ipv6ICMPPacket(t, 1, 4, ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, defaultTTL).Data()).Data()},
		{"IPv6 error quoting a time exceeded", testTranslator(), translateV6, ipv6ICMPPacket(t, 3, 0, ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, defaultTTL).Data()).Data()},
		{"IPv4 quote truncated inside the header", testTranslator(), translateV4, []byte{0x45, 0, 0, 20}},
		{"IPv6 quote truncated inside the header", testTranslator(), translateV6, []byte{0x60, 0, 0, 0}},
		{"IPv4 quote with a wrong version", testTranslator(), translateV4, append([]byte{0x65}, ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()[1:]...)},
		{"IPv4 quote with an illegal source (WKP)", testTranslator(), translateV4, ipv4Segment(t, segmentTCP, net.ParseIP("10.1.2.3").To4(), ipv4Dest, defaultTTL).Data()},
		{"IPv4 quote with an illegal destination (WKP)", testTranslator(), translateV4, ipv4Segment(t, segmentTCP, ipv4Source, net.ParseIP("127.0.0.1").To4(), defaultTTL).Data()},
		{"IPv4 quote with an illegal source (NSP)", nsp, translateV4, ipv4Segment(t, segmentTCP, net.ParseIP("224.0.0.1").To4(), ipv4Dest, defaultTTL).Data()},
		{"IPv4 quote with an illegal destination (NSP)", nsp, translateV4, ipv4Segment(t, segmentTCP, ipv4Source, net.ParseIP("127.0.0.1").To4(), defaultTTL).Data()},
		{"IPv6 quote with an unmappable source", testTranslator(), translateV6, ipv6Segment(t, segmentTCP, ipv6Unmappable, ipv6Dest, defaultTTL).Data()},
		{"IPv6 quote with an unmappable destination", testTranslator(), translateV6, ipv6Segment(t, segmentTCP, ipv6Source, ipv6Unmappable, defaultTTL).Data()},
		{"IPv6 quote embedding an illegal IPv4 address (WKP)", testTranslator(), translateV6, ipv6Segment(t, segmentTCP, ipv6Source, net.ParseIP("64:ff9b::7f00:1"), defaultTTL).Data()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(test.translator, test.quote)
			if result.Packet != nil {
				t.Fatalf("ICMP error with an invalid quote was translated: err=%v", err)
			}
		})
	}
}

// RFC 4443 Section 2.4 (c) (MUST: an ICMPv6 error carries as much of the invoking packet as fits without exceeding
// the minimum IPv6 MTU of 1280 octets) and RFC 1812 Section 4.3.2.3 (SHOULD: an ICMPv4 error stays within 576
// octets): the quote of a translated or generated ICMP error is truncated when it does not fit.
func TestTranslateICMPErrorIsTruncatedToMinimumSizes(t *testing.T) {
	t.Run("ICMPv4 to ICMPv6", func(t *testing.T) {
		quote := ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 1400-ipv4HeaderLength-20), nil).Data()
		result := translateToICMPv6(t, translatorWithMTU(t, 1500), ipv4ICMPPacket(t, 3, 3, quote))
		if len(result.raw) != maxIPv6PacketLength {
			t.Fatalf("translated error is %d octets, want it truncated to %d", len(result.raw), maxIPv6PacketLength)
		}
		if !bytes.Equal(result.icmp.Payload[icmpErrorRestHeaderSize+ipv6HeaderLength:icmpErrorRestHeaderSize+ipv6HeaderLength+20], quote[ipv4HeaderLength:ipv4HeaderLength+20]) {
			t.Fatalf("the truncated quote does not start with the original transport header")
		}
	})
	t.Run("ICMPv6 to ICMPv4", func(t *testing.T) {
		quote := ipv6TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 1200)).Data()
		result := translateToICMPv4(t, testTranslator(), ipv6ICMPPacket(t, 1, 4, quote))
		if len(result.raw) != 576 {
			t.Fatalf("translated error is %d octets, want it truncated to 576", len(result.raw))
		}
	})
	t.Run("generated Time Exceeded for IPv4", func(t *testing.T) {
		packet := withTTL(t, ipv4TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 1200), nil), 1)
		result, err := testTranslator().TranslateIPv4(packet, siit.TranslationOverrides{})
		if !errors.Is(err, siit.ErrTimeExceeded) || len(result.Packet) != maxIPv6PacketLength {
			t.Fatalf("generated Time Exceeded is %d octets (err=%v), want %d", len(result.Packet), err, maxIPv6PacketLength)
		}
	})
	t.Run("generated Time Exceeded for IPv6", func(t *testing.T) {
		packet := withHopLimit(t, ipv6TCPPayloadPacket(t, bytes.Repeat([]byte{0x5a}, 1200)), 1)
		result, err := testTranslator().TranslateIPv6(packet, siit.TranslationOverrides{})
		if !errors.Is(err, siit.ErrTimeExceeded) || len(result.Packet) != 576 {
			t.Fatalf("generated Time Exceeded is %d octets (err=%v), want 576", len(result.Packet), err)
		}
	})
}

// RFC 7915 Section 4.2 (MUST): Fragmentation Needed becomes Packet Too Big with the MTU
// maximum(1280, minimum(MTU + 20, MTU of the IPv6 next hop)). A next-hop MTU of zero (a router predating RFC 1191)
// is replaced by the greatest RFC 1191 Table 7-1 plateau below the Total Length of the original datagram. The RFC
// does not say whether the 20 octets are added to a plateau; the library does, and the plateau rows pin that.
func TestTranslateFragmentationNeededMTU(t *testing.T) {
	tests := []struct {
		name          string
		translatorMTU uint32
		mtu           uint16 // next-hop MTU in the ICMPv4 message
		originalSize  int    // total length of the quoted datagram
		want          uint32
	}{
		{name: "below the IPv6 minimum", translatorMTU: 1280, mtu: 1200, originalSize: 1260, want: 1280},
		{name: "the smallest legal IPv4 MTU", translatorMTU: 1280, mtu: 68, originalSize: 1260, want: 1280},
		{name: "exactly 1260 plus 20", translatorMTU: 1500, mtu: 1260, originalSize: 1500, want: 1280},
		{name: "above the minimum", translatorMTU: 1500, mtu: 1400, originalSize: 1500, want: 1420},
		{name: "ethernet", translatorMTU: 1500, mtu: 1480, originalSize: 1500, want: 1500},
		{name: "larger than the translator MTU", translatorMTU: 1280, mtu: 1500, originalSize: 1500, want: 1280},
		{name: "much larger than the translator MTU", translatorMTU: 1500, mtu: 9000, originalSize: 9000, want: 1500},
		{name: "plateau 8166", translatorMTU: 9000, originalSize: 8500, want: 8186},
		{name: "plateau 4352", translatorMTU: 9000, originalSize: 8166, want: 4372},
		{name: "plateau 2002", translatorMTU: 9000, originalSize: 4352, want: 2022},
		{name: "plateau 1492", translatorMTU: 9000, originalSize: 2002, want: 1512},
		{name: "plateau 1492 for a full ethernet datagram", translatorMTU: 9000, originalSize: 1500, want: 1512},
		{name: "plateau 1006 is below the IPv6 minimum", translatorMTU: 9000, originalSize: 1492, want: 1280},
		{name: "plateau limited by the translator", translatorMTU: 1500, originalSize: 4352, want: 1500},
		{name: "plateau for a small datagram", translatorMTU: 1280, originalSize: 100, want: 1280},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()
			binary.BigEndian.PutUint16(original[2:4], uint16(test.originalSize))
			input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeDestinationUnreachable, 4, 0, test.mtu, original)
			result := translateToICMPv6(t, translatorWithMTU(t, test.translatorMTU), input)
			if result.icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0) {
				t.Fatalf("got %v, want Packet Too Big", result.icmp.TypeCode)
			}
			if got := binary.BigEndian.Uint32(result.icmp.Payload[:4]); got != test.want {
				t.Fatalf("Packet Too Big MTU is %d, want %d", got, test.want)
			}
		})
	}
}

// RFC 7915 Section 5.2 (MUST): the MTU of a Packet Too Big loses the header size difference of 20, and is
// limited by the translator's own IPv6 MTU (the next hop on the IPv4 side cannot take more than that either).
func TestTranslatePacketTooBigMTU(t *testing.T) {
	for _, test := range []struct {
		name          string
		translatorMTU uint32
		mtu           uint32
		want          uint16
	}{
		{name: "minimum IPv6 MTU", translatorMTU: 1280, mtu: 1280, want: 1260},
		{name: "below the IPv6 minimum", translatorMTU: 1280, mtu: 1000, want: 1260},
		{name: "larger than the default MTU", translatorMTU: 1280, mtu: 1500, want: 1260},
		{name: "configured MTU", translatorMTU: 1500, mtu: 1500, want: 1480},
		{name: "larger than the configured MTU", translatorMTU: 1500, mtu: 9000, want: 1480},
		{name: "smaller than the configured MTU", translatorMTU: 1500, mtu: 1400, want: 1380},
		{name: "huge", translatorMTU: 1500, mtu: 0xffffffff, want: 1480},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypePacketTooBig, 0, icmpPointer(test.mtu), ipv6TCPPacket(t, defaultTTL).Data())
			result := translateToICMPv4(t, translatorWithMTU(t, test.translatorMTU), input)
			if result.icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 4) || result.icmp.Seq != test.want {
				t.Fatalf("got %v with MTU %d, want Fragmentation Needed with MTU %d", result.icmp.TypeCode, result.icmp.Seq, test.want)
			}
		})
	}
}

// RFC 7915 Sections 4.2 and 4.3 (MUST) with RFC 7757 Section 3: every address of an ICMP error, in the outer header
// and in the quote, goes through the EAM table, and a quoted TCP checksum follows the translated addresses.
func TestTranslateICMPErrorsUseEAMForOuterAndQuotedAddresses(t *testing.T) {
	translator := testTranslatorWithEAM(eamTable)
	t.Run("IPv4 to IPv6", func(t *testing.T) {
		quote := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, quoteTTL).Data()
		result := translateToICMPv6(t, translator, ipv4ICMPPacket(t, 3, 3, quote))
		if !result.ip.SrcIP.Equal(eamHost2) || !result.ip.DstIP.Equal(eamHost1) {
			t.Fatalf("outer addresses %s -> %s, want %s -> %s", result.ip.SrcIP, result.ip.DstIP, eamHost2, eamHost1)
		}
		requireQuotedTCPv6(t, result.quote(t), eamHost1, eamHost2, quoteTTL)
	})
	t.Run("IPv6 to IPv4", func(t *testing.T) {
		quote := ipv6Segment(t, segmentTCP, eamHost1, eamHost2, defaultTTL).Data()
		input := ipv6ICMPErrorPacket(t, eamHost2, eamHost1, icmpv6DestUnreachable, 4, zeroRestHeader(), quote)
		result := translateToICMPv4(t, translator, input)
		if !result.ip.SrcIP.Equal(ipv4Dest) || !result.ip.DstIP.Equal(ipv4Source) {
			t.Fatalf("outer addresses %s -> %s, want %s -> %s", result.ip.SrcIP, result.ip.DstIP, ipv4Dest, ipv4Source)
		}
		requireQuotedTCPv4(t, result.quote(), ipv4Source, ipv4Dest, defaultTTL)
	})
}

// RFC 7915 Sections 5.2 and 5.3 with RFC 6791 Section 3 (SHOULD, and the only way for the IPv4 side to learn about
// errors from native IPv6 routers): an ICMPv6 error whose source has no IPv4 mapping is translated with the
// configured IPv4 router address as its source, for every error type and whatever the translator's prefix. The
// destination must still map, because the error is addressed to a translated host; a query is never rewritten.
func TestTranslateICMPv6ErrorFromUnmappableRouter(t *testing.T) {
	router := net.ParseIP("2a00:1098:82:72::1")
	translators := map[string]*siit.Translator{
		"well-known prefix":       testTranslator(),
		"network-specific prefix": translatorWithPrefix(t, "2001:db8:64::/96", nil),
		"EAM":                     testTranslatorWithEAM(eamTable),
	}
	// Each translator maps the hosts of the quote to ipv4Source and ipv4Dest.
	hosts := map[string][2]net.IP{
		"well-known prefix":       {ipv4TranslatedSource, ipv4TranslatedDest},
		"network-specific prefix": {net.ParseIP("2001:db8:64::101:101"), net.ParseIP("2001:db8:64::202:202")},
		"EAM":                     {eamHost1, eamHost2},
	}
	errorTypes := []struct {
		name     string
		icmpType uint8
		code     uint8
		rest     []byte
		want     layers.ICMPv4TypeCode
	}{
		{"destination unreachable", 1, 0, zeroRestHeader(), layers.CreateICMPv4TypeCode(3, 1)},
		{"packet too big", 2, 0, icmpPointer(1280), layers.CreateICMPv4TypeCode(3, 4)},
		{"time exceeded", 3, 0, zeroRestHeader(), layers.CreateICMPv4TypeCode(11, 0)},
		{"parameter problem", 4, 0, icmpPointer(6), layers.CreateICMPv4TypeCode(12, 0)},
	}
	for name, translator := range translators {
		for _, errorType := range errorTypes {
			t.Run(name+"/"+errorType.name, func(t *testing.T) {
				// ipv4Dest's host sent the quoted packet to ipv4Source's host and the router could not forward it.
				quote := ipv6Segment(t, segmentTCP, hosts[name][1], hosts[name][0], defaultTTL).Data()
				input := ipv6ICMPErrorPacket(t, router, hosts[name][1], errorType.icmpType, errorType.code, errorType.rest, quote)
				result := translateToICMPv4(t, translator, input)
				if !result.ip.SrcIP.Equal(ipv4RouterAddress) || !result.ip.DstIP.Equal(ipv4Dest) || result.icmp.TypeCode != errorType.want {
					t.Fatalf("got %s -> %s %v, want %s -> %s %v", result.ip.SrcIP, result.ip.DstIP, result.icmp.TypeCode, ipv4RouterAddress, ipv4Dest, errorType.want)
				}
				requireQuotedTCPv4(t, result.quote(), ipv4Dest, ipv4Source, defaultTTL)
			})
		}
	}
	t.Run("a destination without mapping is not translated", func(t *testing.T) {
		quote := ipv6Segment(t, segmentTCP, ipv6Unmappable, ipv6Dest, defaultTTL).Data()
		input := ipv6ICMPErrorPacket(t, router, net.ParseIP("2a10:3781:56d5:8::e7"), icmpv6DestUnreachable, 0, zeroRestHeader(), quote)
		result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		if result.Packet != nil {
			t.Fatalf("ICMPv6 error to an unmappable destination was translated: err=%v", err)
		}
	})
	t.Run("an echo request from an unmappable source is not translated", func(t *testing.T) {
		input := ipv6Segment(t, segmentICMP, router, ipv6Dest, defaultTTL)
		result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		if result.Packet != nil {
			t.Fatalf("ICMPv6 query from an unmappable source was translated: err=%v", err)
		}
	})
}

// RFC 7915 Sections 4.1 and 5.1 (SHOULD): the Time Exceeded message that the library generates for an expired
// IPv4 packet is addressed to the translated IPv4 sender, so feeding it back through TranslateIPv6 must produce a
// deliverable ICMPv4 Time Exceeded for that sender.
func TestGeneratedTimeExceededCanBeTranslatedBack(t *testing.T) {
	generated, err := testTranslator().TranslateIPv4(ipv4TCPPacket(t, 1), siit.TranslationOverrides{})
	if !errors.Is(err, siit.ErrTimeExceeded) || generated.Packet == nil {
		t.Fatalf("expired packet did not generate Time Exceeded: err=%v", err)
	}
	result := translateToICMPv4(t, testTranslator(), gopacket.NewPacket(generated.Packet, layers.LayerTypeIPv6, gopacket.Default))
	if !result.ip.DstIP.Equal(ipv4Source) || !result.ip.SrcIP.Equal(ipv4RouterAddress) || result.icmp.TypeCode != layers.CreateICMPv4TypeCode(icmpv4TimeExceeded, 0) {
		t.Fatalf("generated Time Exceeded was not translated into a deliverable ICMPv4 error: %v", result.packet.ErrorLayer())
	}
}
