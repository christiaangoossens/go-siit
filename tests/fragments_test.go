package siit_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.1, 5.1 and 5.1.1 (MUST): fragments are translated one by one, without reassembly. An IPv4
// fragment gets an IPv6 Fragment header carrying its offset, More Fragments flag and Identification (extended to 32
// bits); an IPv6 Fragment header becomes the IPv4 offset, MF flag and the low 16 bits of the Identification, with DF
// cleared. IPv4 options and IPv6 extension headers in front of the fragment header are skipped, an atomic fragment
// (offset 0, M=0) is a fragment with MF=0, and the payload is carried over unchanged.
func TestTranslateFragments(t *testing.T) {
	tests := []struct {
		name    string
		offset  uint16
		more    bool
		payload []byte // fragment payload; offset 0 gets a TCP header in front
		id      uint32
		v6Only  bool // an atomic fragment only exists in IPv6; an unfragmented IPv4 packet gets no Fragment header
	}{
		{name: "first fragment", offset: 0, more: true, payload: []byte{0, 1, 2, 3}, id: 0x1234},
		{name: "middle fragment", offset: 5, more: true, payload: bytes.Repeat([]byte{0xcd}, 16), id: 0x1234},
		{name: "last fragment", offset: 9, more: false, payload: []byte{8, 9, 10, 11, 12}, id: 0x1234},
		{name: "atomic fragment", offset: 0, more: false, payload: []byte("atom"), id: 0xabcd, v6Only: true},
		{name: "maximum offset", offset: 8191, more: false, payload: []byte("final"), id: 0xffff},
	}
	for _, test := range tests {
		payload := test.payload
		if test.offset == 0 {
			payload = tcpFragmentPayload(test.payload)
		}
		for _, withOptions := range []bool{false, true} {
			if test.v6Only {
				break
			}
			t.Run(fmt.Sprintf("IPv4 to IPv6/%s/options %t", test.name, withOptions), func(t *testing.T) {
				ip := &layers.IPv4{
					Version: 4, IHL: 5, Id: uint16(test.id), TTL: defaultTTL, FragOffset: test.offset,
					Protocol: layers.IPProtocolTCP, SrcIP: ipv4Source, DstIP: ipv4Dest,
				}
				if test.more {
					ip.Flags = layers.IPv4MoreFragments
				}
				if withOptions {
					ip.Options = []layers.IPv4Option{ipv4NOP, ipv4NOP, ipv4NOP, ipv4NOP}
				}
				input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
				packet := translateIPv4Raw(t, input.Data())
				ip6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				fragment, ok := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
				if !ok || ip6.NextHeader != layers.IPProtocolIPv6Fragment || int(ip6.Length) != 8+len(payload) {
					t.Fatalf("fragmented IPv4 packet did not get a valid IPv6 Fragment header: %v", packet.ErrorLayer())
				}
				if fragment.NextHeader != layers.IPProtocolTCP || fragment.FragmentOffset != test.offset || fragment.MoreFragments != test.more || fragment.Identification != test.id {
					t.Fatalf("unexpected translated fragment metadata: %+v", fragment)
				}
				if !bytes.Equal(fragment.Payload, payload) {
					t.Fatalf("fragment payload changed: got %v, want %v", fragment.Payload, payload)
				}
			})
		}
		t.Run(fmt.Sprintf("IPv6 to IPv4/%s", test.name), func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, FragmentOffset: test.offset, MoreFragments: test.more, Identification: 0xa5a50000 | test.id}
			input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, payload), layers.LayerTypeIPv6, gopacket.Default)
			translated := translateToIPv4Packet(t, input).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if translated.Protocol != layers.IPProtocolTCP || translated.FragOffset != test.offset || (translated.Flags&layers.IPv4MoreFragments != 0) != test.more ||
				translated.Flags&layers.IPv4DontFragment != 0 || uint32(translated.Id) != test.id {
				t.Fatalf("unexpected translated IPv4 fragment metadata: %+v", translated)
			}
			if translated.Length != uint16(ipv4HeaderLength+len(payload)) || translated.Checksum != ipv4HeaderChecksum(translated) || !bytes.Equal(translated.Payload, payload) {
				t.Fatalf("translated IPv6 fragment has an invalid length, checksum or payload: %+v", translated)
			}
		})
	}

	t.Run("IPv6 to IPv4/Hop-by-Hop before the Fragment header", func(t *testing.T) {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6HopByHop, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, MoreFragments: true, Identification: 0x01020304}
		payload := tcpFragmentPayload([]byte{0, 1, 2, 3})
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(cat(optionsHeader(layers.IPProtocolIPv6Fragment), ipv6FragmentHeader(fragment), payload))), layers.LayerTypeIPv6, gopacket.Default)
		translated := translateToIPv4Packet(t, input).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if translated.Protocol != layers.IPProtocolTCP || translated.Flags&layers.IPv4MoreFragments == 0 || translated.Id != 0x0304 || !bytes.Equal(translated.Payload, payload) {
			t.Fatalf("fragment behind Hop-by-Hop was not translated correctly: %+v", translated)
		}
	})
	t.Run("IPv6 to IPv4/ESP behind the Fragment header", func(t *testing.T) {
		// ESP is the one header that may follow a Fragment header (RFC 7915 Section 5.1.1).
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolESP, Identification: 0x01020304}
		input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 8)), layers.LayerTypeIPv6, gopacket.Default)
		translated := translateToIPv4Packet(t, input).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if translated.Protocol != layers.IPProtocolESP || translated.FragOffset != 0 {
			t.Fatalf("unexpected ESP fragment translation: %+v", translated)
		}
	})
}

// RFC 7915 Section 1.2 (fragmented ICMP, MUST NOT be translated), Section 5.1.1 (a Fragment header followed by
// an extension header other than ESP is dropped) and RFC 8200 Section 4.5 (every fragment but the last has a
// payload that is a multiple of 8 octets; the Fragment header must be complete): packets that cannot be translated
// as fragments are not translated at all.
func TestTranslateDropsInvalidFragments(t *testing.T) {
	icmpv4 := []byte{layers.ICMPv4TypeDestinationUnreachable, 3, 0, 0, 0, 0, 0, 0}
	icmpv6 := []byte{layers.ICMPv6TypeDestinationUnreachable, 4, 0, 0, 0, 0, 0, 0}
	v4Fragment := func(protocol layers.IPProtocol, flags layers.IPv4Flag, offset uint16, payload []byte) gopacket.Packet {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Flags: flags, FragOffset: offset, Protocol: protocol, SrcIP: ipv4Source, DstIP: ipv4Dest}
		return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
	}
	v6Fragment := func(next layers.IPProtocol, more bool, offset uint16, payload []byte) gopacket.Packet {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		fragment := &layers.IPv6Fragment{NextHeader: next, MoreFragments: more, FragmentOffset: offset, Identification: 0x01020304}
		return gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, payload), layers.LayerTypeIPv6, gopacket.Default)
	}
	destinationOptions := cat([]byte{byte(layers.IPProtocolTCP), 0, 0, 0, 0, 0, 0, 0}, tcpFragmentPayload([]byte("extension")))
	tests := []struct {
		name   string
		v4     bool
		packet gopacket.Packet
	}{
		{"IPv4 first ICMP fragment", true, v4Fragment(layers.IPProtocolICMPv4, layers.IPv4MoreFragments, 0, icmpv4)},
		{"IPv4 middle ICMP fragment", true, v4Fragment(layers.IPProtocolICMPv4, layers.IPv4MoreFragments, 1, icmpv4)},
		{"IPv4 final ICMP fragment", true, v4Fragment(layers.IPProtocolICMPv4, 0, 1, icmpv4)},
		{"IPv6 first ICMP fragment", false, v6Fragment(layers.IPProtocolICMPv6, true, 0, icmpv6)},
		{"IPv6 final ICMP fragment", false, v6Fragment(layers.IPProtocolICMPv6, false, 1, icmpv6)},
		{"IPv6 unaligned non-final fragment", false, v6Fragment(layers.IPProtocolTCP, true, 0, make([]byte, 7))},
		{"IPv6 truncated Fragment header", false, gopacket.NewPacket(serializeTestPacket(t, &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}, gopacket.Payload(make([]byte, 4))), layers.LayerTypeIPv6, gopacket.Default)},
		{"IPv6 fragment followed by Destination Options", false, v6Fragment(layers.IPProtocolIPv6Destination, false, 0, destinationOptions)},
		{"IPv6 fragment followed by Routing", false, v6Fragment(layers.IPProtocolIPv6Routing, false, 0, make([]byte, 8))},
		{"IPv6 fragment followed by Hop-by-Hop", false, v6Fragment(layers.IPProtocolIPv6HopByHop, false, 0, make([]byte, 8))},
		{"IPv6 fragment followed by AH", false, v6Fragment(layers.IPProtocolAH, false, 0, make([]byte, 8))},
		{"IPv6 fragment followed by Mobility Header", false, v6Fragment(layers.IPProtocol(135), false, 0, make([]byte, 8))},
		{"IPv6 fragment followed by another Fragment header", false, v6Fragment(layers.IPProtocolIPv6Fragment, false, 0, make([]byte, 8))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result siit.TranslatedPacket
			var err error
			if test.v4 {
				result, err = testTranslator().TranslateIPv4(test.packet, siit.TranslationOverrides{})
			} else {
				result, err = testTranslator().TranslateIPv6(test.packet, siit.TranslationOverrides{})
			}
			if result.Packet != nil {
				t.Fatalf("packet was translated: err=%v", err)
			}
		})
	}
}

func tcpFragmentPayload(payload []byte) []byte {
	segment := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], uint16(testSourcePort))
	binary.BigEndian.PutUint16(segment[2:4], uint16(testTCPDestinationPort))
	segment[12] = 5 << 4
	copy(segment[20:], payload)
	return segment
}

func ipv6FragmentHeader(fragment *layers.IPv6Fragment) []byte {
	header := make([]byte, 8)
	header[0] = byte(fragment.NextHeader)
	header[1] = fragment.Reserved1
	fragmentBits := fragment.FragmentOffset << 3
	fragmentBits |= uint16(fragment.Reserved2) << 1
	binary.BigEndian.PutUint16(header[2:4], fragmentBits)
	if fragment.MoreFragments {
		header[3] |= 1
	}
	binary.BigEndian.PutUint32(header[4:8], fragment.Identification)
	return header
}

func serializeIPv6FragmentPacket(t *testing.T, ip *layers.IPv6, fragment *layers.IPv6Fragment, payload []byte) []byte {
	t.Helper()
	return serializeTestPacket(t, ip, gopacket.Payload(append(ipv6FragmentHeader(fragment), payload...)))
}

// RFC 7915 Section 4.5 (SHOULD, see the README) and Section 1.2: a stateless translator cannot compute the UDP
// checksum of a fragmented datagram, so the first fragment of a zero-checksum IPv4 UDP datagram is silently dropped.
func TestTranslateIPv4ZeroChecksumUDPFirstFragmentDropped(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP,
		Flags: layers.IPv4MoreFragments, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	udp := make([]byte, 16)
	binary.BigEndian.PutUint16(udp[0:2], testSourcePort)
	binary.BigEndian.PutUint16(udp[2:4], dnsPort)
	binary.BigEndian.PutUint16(udp[4:6], 100) // length of the whole datagram; checksum (octets 6-7) stays zero
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(udp)), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	requireDropped(t, result, err)
}

// RFC 7915 Sections 4.5 and 5.5 (MUST): with a mapping that changes the pseudo-header the transport checksum must
// be updated, which a stateless translator can do for the first fragment because the checksum field is in its header.
func TestTranslateFirstFragmentUpdatesChecksum(t *testing.T) {
	translator := testTranslatorWithEAM(eamTable)
	// Every fragment but the last must be a multiple of 8 octets: a TCP header is 20 octets, a UDP header 8.
	for _, kind := range []string{segmentTCP, segmentUDP} {
		content := bytes.Repeat([]byte{1}, map[string]int{segmentTCP: 28, segmentUDP: 24}[kind])
		t.Run(kind+"/IPv4 to IPv6", func(t *testing.T) {
			ip := &layers.IPv4{
				Version: 4, IHL: 5, Id: 0x1234, TTL: defaultTTL, Protocol: layers.IPProtocolTCP,
				Flags: layers.IPv4MoreFragments, SrcIP: ipv4Source, DstIP: ipv4Dest,
			}
			if kind == segmentUDP {
				ip.Protocol = layers.IPProtocolUDP
			}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(fragmentSegment(t, kind, ip, content))), layers.LayerTypeIPv4, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			fragment, ok := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
			if !ok {
				t.Fatalf("missing IPv6 fragment: %v", packet.ErrorLayer())
			}
			requireFragmentChecksum(t, kind, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), fragment.Payload)
		})
		t.Run(kind+"/IPv6 to IPv4", func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: eamHost1, DstIP: eamHost2}
			next := layers.IPProtocolTCP
			if kind == segmentUDP {
				next = layers.IPProtocolUDP
			}
			fragment := &layers.IPv6Fragment{NextHeader: next, MoreFragments: true, Identification: 0x01020304}
			input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, fragmentSegment(t, kind, ip, content)), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(input, siit.TranslationOverrides{})
			})
			translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			requireFragmentChecksum(t, kind, translated, translated.Payload)
		})
	}
}

// fragmentSegment builds the first fragment's payload: a TCP or UDP segment whose checksum covers the pseudo-header of
// the original packet (only meaningful for the first fragment of a datagram that is complete in itself).
func fragmentSegment(t *testing.T, kind string, network gopacket.NetworkLayer, payload []byte) []byte {
	t.Helper()
	if kind == segmentTCP {
		return tcpSegment(t, network, payload)
	}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(network); err != nil {
		t.Fatal(err)
	}
	return serializeTestPacket(t, udp, gopacket.Payload(payload))
}

func requireFragmentChecksum(t *testing.T, kind string, network gopacket.NetworkLayer, segment []byte) {
	t.Helper()
	if kind == segmentTCP {
		tcp := gopacket.NewPacket(segment, layers.LayerTypeTCP, gopacket.Default).Layer(layers.LayerTypeTCP).(*layers.TCP)
		if want := recalculatedTCPChecksum(t, network, tcp); tcp.Checksum != want {
			t.Fatalf("TCP checksum is %#x, want %#x for the translated pseudo-header", tcp.Checksum, want)
		}
		return
	}
	udp := gopacket.NewPacket(segment, layers.LayerTypeUDP, gopacket.Default).Layer(layers.LayerTypeUDP).(*layers.UDP)
	if want := recalculatedUDPChecksum(t, network, udp); udp.Checksum != want {
		t.Fatalf("UDP checksum is %#x, want %#x for the translated pseudo-header", udp.Checksum, want)
	}
}
