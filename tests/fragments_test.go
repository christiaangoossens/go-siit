package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Section 5.1.1 (MUST): "If the Next Header field of the Fragment Header is not an extension header (except
// ESP), then Fragment Offset MUST be copied from the Fragment Offset field of the IPv6 Fragment Header."
//
// Fragments are translated one by one, without reassembly, in both directions (RFC 7915 Sections 4.1 and 5.1.1).
// Towards IPv4 only the low 16 bits of the Identification are kept.
//
// RFC 7915 Section 4.1 (MUST): "otherwise, the protocol field MUST be copied from the IPv4 header."
//
// RFC 7915 Section 4.1: "Total length value from the IPv4 header, plus 8 for the Fragment Header, minus the size of
// the IPv4 header and IPv4 options, if present."
//
// RFC 7915 Section 5.1.1 (MUST): "the Total Length MUST be set to Payload Length value from IPv6 header, minus the
// length of the extension headers up to the Fragmentation Header, minus 8 for the Fragment Header, plus the size of
// the IPv4 header."
//
// RFC 7915 Section 5.1.1: "The IPv4 Don't Fragment (DF) flag is cleared (set to zero), allowing this packet to be
// further fragmented by IPv4 routers."
//
// The DF bit stays clear above 1260 octets too, where an unfragmented packet would get it.
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

	t.Run("IPv4 to IPv6/Don't Fragment and More Fragments", func(t *testing.T) {
		ip := &layers.IPv4{
			Version: 4, IHL: 5, Id: 0x1234, TTL: defaultTTL, Flags: layers.IPv4DontFragment | layers.IPv4MoreFragments,
			Protocol: layers.IPProtocolTCP, SrcIP: ipv4Source, DstIP: ipv4Dest,
		}
		_, fragment := translatedIPv4Fragment(t, ip, tcpFragmentPayload([]byte{0, 1, 2, 3}))
		if !fragment.MoreFragments || fragment.Identification != 0x1234 {
			t.Fatalf("unexpected translated fragment metadata: %+v", fragment)
		}
	})
	for _, test := range []struct {
		name     string
		protocol layers.IPProtocol
		offset   uint16
	}{
		{"UDP first fragment", layers.IPProtocolUDP, 0},
		{"GRE middle fragment", layers.IPProtocolGRE, 5},
	} {
		t.Run("IPv4 to IPv6/"+test.name, func(t *testing.T) {
			ip := &layers.IPv4{
				Version: 4, IHL: 5, Id: 0x1234, TTL: defaultTTL, Flags: layers.IPv4MoreFragments, FragOffset: test.offset,
				Protocol: test.protocol, SrcIP: ipv4Source, DstIP: ipv4Dest,
			}
			payload := bytes.Repeat([]byte{0xcd}, 16)
			if test.protocol == layers.IPProtocolUDP {
				payload = fragmentSegment(t, segmentUDP, ip, make([]byte, 24)) // a non-zero checksum
			}

			ip6, fragment := translatedIPv4Fragment(t, ip, payload)
			if fragment.NextHeader != test.protocol || int(ip6.Length) != 8+len(payload) {
				t.Fatalf("got Next Header %d and Payload Length %d, want %d and %d", fragment.NextHeader, ip6.Length, test.protocol, 8+len(payload))
			}
		})
	}

	t.Run("IPv6 to IPv4/Hop-by-Hop before the Fragment header", func(t *testing.T) {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6HopByHop, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, MoreFragments: true, Identification: 0x01020304}
		payload := tcpFragmentPayload(make([]byte, 1244)) // a 1284-octet IPv4 fragment
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(cat(optionsHeader(layers.IPProtocolIPv6Fragment), ipv6FragmentHeader(fragment), payload))), layers.LayerTypeIPv6, gopacket.Default)
		translated := translatedIPv6Fragment(t, input)
		if translated.Protocol != layers.IPProtocolTCP || translated.Flags&layers.IPv4MoreFragments == 0 || translated.Id != 0x0304 || !bytes.Equal(translated.Payload, payload) {
			t.Fatalf("fragment behind Hop-by-Hop was not translated correctly: %+v", translated)
		}

		if translated.Length != 1284 || translated.Checksum != ipv4HeaderChecksum(translated) || translated.Flags&layers.IPv4DontFragment != 0 {
			t.Fatalf("got Total Length %d, checksum %#x and flags %v, want 1284, a valid checksum and no DF", translated.Length, translated.Checksum, translated.Flags)
		}
	})
	t.Run("IPv6 to IPv4/No Next Header in an atomic fragment", func(t *testing.T) {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolNoNextHeader, Identification: 0x01020304}
		input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, nil), layers.LayerTypeIPv6, gopacket.Default)
		translated := translatedIPv6Fragment(t, input)
		if translated.Protocol != layers.IPProtocolNoNextHeader || translated.Flags != 0 || translated.FragOffset != 0 || translated.Id != 0x0304 || translated.Length != ipv4HeaderLength {
			t.Fatalf("unexpected translated atomic fragment: %+v", translated)
		}
	})
	for _, more := range []bool{true, false} {
		t.Run(fmt.Sprintf("IPv6 to IPv4/1440-octet fragment, M=%t", more), func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, FragmentOffset: 180, MoreFragments: more, Identification: 0x01020304}
			input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 1440)), layers.LayerTypeIPv6, gopacket.Default)
			translated := translatedIPv6Fragment(t, input)
			if translated.Length != ipv4HeaderLength+1440 || translated.Flags&layers.IPv4DontFragment != 0 || translated.Id != 0x0304 {
				t.Fatalf("got Total Length %d, flags %v and ID %#x, want %d, no DF and 0x0304", translated.Length, translated.Flags, translated.Id, ipv4HeaderLength+1440)
			}

			if (translated.Flags&layers.IPv4MoreFragments != 0) != more || translated.FragOffset != 180 {
				t.Fatalf("got flags %v and offset %d, want MF=%t and 180", translated.Flags, translated.FragOffset, more)
			}
		})
	}
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

// RFC 7915 Section 1.2 (fragmented ICMP is not translated), Section 5.1.1 (a Fragment header followed by
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
	// surroundedFragment puts the same extension header before and after the Fragment header.
	surroundedFragment := func(extension layers.IPProtocol) gopacket.Packet {
		ip := &layers.IPv6{Version: 6, NextHeader: extension, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		fragment := &layers.IPv6Fragment{NextHeader: extension, Identification: 0x01020304}
		headers := cat(optionsHeader(layers.IPProtocolIPv6Fragment), ipv6FragmentHeader(fragment), optionsHeader(layers.IPProtocolTCP))
		return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(cat(headers, tcpFragmentPayload(nil)))), layers.LayerTypeIPv6, gopacket.Default)
	}
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
		{"IPv6 Hop-by-Hop, Fragment, Hop-by-Hop", false, surroundedFragment(layers.IPProtocolIPv6HopByHop)},
		{"IPv6 Destination Options, Fragment, Destination Options", false, surroundedFragment(layers.IPProtocolIPv6Destination)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result translation
			var err error
			if test.v4 {
				result, err = translateIPv4(t, testTranslator(), test.packet)
			} else {
				result, err = translateIPv6(t, testTranslator(), test.packet)
			}
			if result.packet != nil {
				t.Fatalf("packet was translated: err=%v", err)
			}
		})
	}

	// RFC 791 Section 2.3: "(the second portion might not be an integral multiple of 8 octets, but the first must be)"
	//
	// RFC 8200 Section 4.5: "If the length of a fragment, as derived from the fragment packet's Payload Length field,
	// is not a multiple of 8 octets and the M flag of that fragment is 1, then that fragment must be discarded"
	//
	// After translation, an unaligned IPv4 fragment with MF=1 would be such an IPv6 fragment, so it is rejected like
	// the IPv6 one above.
	for _, offset := range []uint16{0, 1} {
		t.Run(fmt.Sprintf("IPv4 unaligned non-final fragment at offset %d", offset), func(t *testing.T) {
			result, err := translateIPv4(t, testTranslator(), v4Fragment(layers.IPProtocolGRE, layers.IPv4MoreFragments, offset, make([]byte, 7)))
			if !errors.Is(err, siit.ErrInvalidPacket) || result.packet != nil {
				t.Fatalf("got err=%v, packet length %d, want ErrInvalidPacket", err, len(result.packet))
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

// translatedIPv4Fragment translates an IPv4 fragment and returns the IPv6 header and its Fragment header.
func translatedIPv4Fragment(t *testing.T, ip *layers.IPv4, payload []byte) (*layers.IPv6, *layers.IPv6Fragment) {
	t.Helper()
	packet := translateIPv4Raw(t, serializeTestPacket(t, ip, gopacket.Payload(payload)))
	fragment, ok := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
	if !ok {
		t.Fatalf("missing IPv6 Fragment header: %v", packet.ErrorLayer())
	}

	return packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), fragment
}

// translatedIPv6Fragment translates an IPv6 fragment of up to 1500 octets and returns the IPv4 header.
func translatedIPv6Fragment(t *testing.T, input gopacket.Packet) *layers.IPv4 {
	t.Helper()
	result := mustTranslate(t, func() (translation, error) {
		return translateIPv6(t, translatorWithMTU(t, 1500), input)
	})

	return gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
}

// RFC 7915 Section 5.1.1 (SHOULD): "If the Next Header field of the Fragment Header is an extension header (except
// ESP), then the packet SHOULD be dropped and logged."
//
// The error lets the caller log it.
func TestTranslateIPv6FragmentWithExtensionHeaderIsReported(t *testing.T) {
	for _, next := range []layers.IPProtocol{layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Destination, layers.IPProtocolAH} {
		t.Run(next.String(), func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			fragment := &layers.IPv6Fragment{NextHeader: next}
			input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 8)), layers.LayerTypeIPv6, gopacket.Default)

			result, err := translateIPv6(t, testTranslator(), input)
			if result.packet != nil || !errors.Is(err, siit.ErrUnsupportedProtocol) {
				t.Fatalf("got err=%v, packet length %d, want ErrUnsupportedProtocol", err, len(result.packet))
			}
		})
	}
}

// RFC 7915 Section 4.5 (SHOULD): "when a stateless translator receives the first fragment of a fragmented UDP IPv4
// packet and the checksum field is zero, the translator SHOULD drop the packet and generate a system management
// event that specifies at least the IP addresses and port numbers in the packet."
//
// The returned error is that event.
func TestTranslateIPv4ZeroChecksumUDPFirstFragmentRejected(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP,
		Flags: layers.IPv4MoreFragments, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	udp := make([]byte, 16)
	binary.BigEndian.PutUint16(udp[0:2], testSourcePort)
	binary.BigEndian.PutUint16(udp[2:4], dnsPort)
	binary.BigEndian.PutUint16(udp[4:6], 100) // length of the whole datagram; checksum (octets 6-7) stays zero
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(udp)), layers.LayerTypeIPv4, gopacket.Default)
	result, err := translateIPv4(t, testTranslator(), input)
	requireZeroUDPChecksumError(t, result, err, endpoint(ipv4Source, testSourcePort), endpoint(ipv4Dest, dnsPort))
}

// RFC 8200 Section 8.1: "IPv6 receivers must discard UDP packets containing a zero checksum and should log the error."
//
// The first fragment holds the UDP header, so it is rejected with the same error as an unfragmented datagram.
func TestTranslateIPv6ZeroChecksumUDPFirstFragmentRejected(t *testing.T) {
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolUDP, MoreFragments: true, Identification: 0x01020304}
	udp := make([]byte, 16)
	binary.BigEndian.PutUint16(udp[0:2], testSourcePort)
	binary.BigEndian.PutUint16(udp[2:4], dnsPort)
	binary.BigEndian.PutUint16(udp[4:6], 100) // length of the whole datagram; checksum (octets 6-7) stays zero

	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, udp), layers.LayerTypeIPv6, gopacket.Default)
	result, err := translateIPv6(t, testTranslator(), input)
	requireZeroUDPChecksumError(t, result, err, endpoint(ipv6Source, testSourcePort), endpoint(ipv6Dest, dnsPort))
}

// RFC 7915 Section 4.5 (MUST): "the recalculation and updating of the transport-layer headers that contain
// pseudo-headers need to be performed. Translators MUST do this for TCP and ICMP packets and for UDP packets that
// contain a UDP checksum"
//
// RFC 7915 Section 5.5 (MUST): "Translators MUST do this for TCP, UDP, and ICMP."
//
// The EAM mapping changes the pseudo-header sum, so the checksum must really change; only the first fragment holds it.
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
			result := mustTranslate(t, func() (translation, error) {
				return translateIPv4(t, translator, input)
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
			result := mustTranslate(t, func() (translation, error) {
				return translateIPv6(t, translator, input)
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
