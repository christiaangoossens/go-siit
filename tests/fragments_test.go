package siit_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.1 and 5.1.1: IPv4 options are ignored while fragment metadata and payloads are translated.
func TestTranslateIPv4FragmentsWithOptions(t *testing.T) {
	tests := []struct {
		name    string
		offset  uint16
		more    bool
		payload []byte
	}{
		{name: "first fragment", offset: 0, more: true, payload: []byte{0, 1, 2, 3}},
		{name: "non-first fragment", offset: 1, more: false, payload: []byte{8, 9, 10, 11, 12, 13, 14, 15}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fragmentPayload := test.payload
			if test.offset == 0 {
				fragmentPayload = tcpFragmentPayload(test.payload)
			}
			ip := &layers.IPv4{
				Version: 4, IHL: 5, Id: 0x1234, TTL: defaultTTL,
				FragOffset: test.offset, Protocol: layers.IPProtocolTCP, SrcIP: ipv4Source, DstIP: ipv4Dest,
				Options: []layers.IPv4Option{{OptionType: 1, OptionLength: 1}, {OptionType: 1, OptionLength: 1}},
			}
			if test.more {
				ip.Flags = layers.IPv4MoreFragments
			}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(fragmentPayload)), layers.LayerTypeIPv4, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			ip6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || ip6.Length != uint16(len(result)-ipv6HeaderLength) {
				t.Fatalf("translated IPv4 fragment has invalid IPv6 payload length: %v", packet.ErrorLayer())
			}
			fragment, ok := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
			if !ok {
				t.Fatalf("fragmented IPv4 packet lost its IPv6 Fragment Header: %v", packet.ErrorLayer())
			}
			if fragment.NextHeader != layers.IPProtocolTCP || fragment.FragmentOffset != test.offset || fragment.MoreFragments != test.more || fragment.Identification != uint32(ip.Id) {
				t.Fatalf("unexpected translated fragment metadata: %+v", fragment)
			}
			if !bytes.Equal(fragment.Payload, fragmentPayload) {
				t.Fatalf("fragment payload changed: got %v, want %v", fragment.Payload, fragmentPayload)
			}
		})
	}
}

// RFC 7915 Section 5.1.1: IPv6 Fragment Headers translate to IPv4 fragment metadata without reassembly.
func TestTranslateIPv6Fragments(t *testing.T) {
	tests := []struct {
		name    string
		offset  uint16
		more    bool
		payload []byte
	}{
		{name: "first fragment", offset: 0, more: true, payload: []byte{0, 1, 2, 3}},
		{name: "non-first fragment", offset: 1, more: false, payload: []byte{8, 9, 10, 11, 12, 13, 14, 15}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fragmentPayload := test.payload
			if test.offset == 0 {
				fragmentPayload = tcpFragmentPayload(test.payload)
			}
			ip := &layers.IPv6{
				Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
				SrcIP: ipv6Source, DstIP: ipv6Dest,
			}
			fragment := &layers.IPv6Fragment{
				NextHeader: layers.IPProtocolTCP, FragmentOffset: test.offset,
				MoreFragments: test.more, Identification: 0x01020304,
			}
			input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, fragmentPayload), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
			translated, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok {
				t.Fatalf("fragmented IPv6 packet did not produce IPv4: %v", packet.ErrorLayer())
			}
			if translated.Protocol != layers.IPProtocolTCP || translated.FragOffset != test.offset || (translated.Flags&layers.IPv4MoreFragments != 0) != test.more || translated.Flags&layers.IPv4DontFragment != 0 || translated.Id != 0x0304 {
				t.Fatalf("unexpected translated IPv4 fragment metadata: %+v", translated)
			}
			if translated.Length != uint16(len(result)) || translated.Checksum != ipv4HeaderChecksum(translated) {
				t.Fatalf("translated IPv6 fragment has invalid IPv4 length or checksum: length=%d checksum=%#x", translated.Length, translated.Checksum)
			}
			if !bytes.Equal(translated.Payload, fragmentPayload) {
				t.Fatalf("fragment payload changed: got %v, want %v", translated.Payload, fragmentPayload)
			}
		})
	}
}

// RFC 7915 Section 1.2: fragmented ICMP and ICMPv6 packets are not translated.
func TestTranslateRejectsFragmentedICMP(t *testing.T) {
	ipv4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Flags: layers.IPv4MoreFragments,
		Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	ipv4Payload := []byte{layers.ICMPv4TypeDestinationUnreachable, 3, 0, 0, 0, 0, 0, 0}
	ipv4Input := gopacket.NewPacket(serializeTestPacket(t, ipv4, gopacket.Payload(ipv4Payload)), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(ipv4Input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("fragmented ICMPv4 packet was translated: err=%v", err)
	}

	ipv6 := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{
		NextHeader: layers.IPProtocolICMPv6, MoreFragments: true, Identification: 0x01020304,
	}
	ipv6Payload := []byte{layers.ICMPv6TypeDestinationUnreachable, 4, 0, 0, 0, 0, 0, 0}
	ipv6Input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ipv6, fragment, ipv6Payload), layers.LayerTypeIPv6, gopacket.Default)
	result, err = testTranslator().TranslateIPv6(ipv6Input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("fragmented ICMPv6 packet was translated: err=%v", err)
	}
}

// RFC 7915 Section 1.2: final and non-first ICMP fragments are not translated.
func TestTranslateRejectsFinalNonFirstICMPFragments(t *testing.T) {
	ipv4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, FragOffset: 1,
		Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	ipv4Payload := []byte{layers.ICMPv4TypeDestinationUnreachable, 3, 0, 0, 0, 0, 0, 0}
	ipv4Input := gopacket.NewPacket(serializeTestPacket(t, ipv4, gopacket.Payload(ipv4Payload)), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(ipv4Input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("final non-first ICMPv4 fragment was translated: err=%v", err)
	}

	ipv6 := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{
		NextHeader: layers.IPProtocolICMPv6, FragmentOffset: 1, Identification: 0x01020304,
	}
	ipv6Payload := []byte{layers.ICMPv6TypeDestinationUnreachable, 4, 0, 0, 0, 0, 0, 0}
	ipv6Input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ipv6, fragment, ipv6Payload), layers.LayerTypeIPv6, gopacket.Default)
	result, err = testTranslator().TranslateIPv6(ipv6Input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("final non-first ICMPv6 fragment was translated: err=%v", err)
	}
}

// RFC 8200: every non-final fragment payload must be a multiple of 8 octets.
func TestTranslateRejectsUnalignedNonFinalFragment(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, MoreFragments: true, Identification: 0x01020304}
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 7)), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("non-final fragment with an unaligned payload was translated: err=%v", err)
	}
}

// RFC 7915 Section 5.1.1: an IPv6 Fragment Header must be complete before translation.
func TestTranslateRejectsTruncatedIPv6FragmentHeader(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 4))), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("truncated IPv6 Fragment Header was translated: err=%v", err)
	}
}

// RFC 7915 Section 5.1.1: maximum fragment offsets are preserved and Identification uses its low-order 16 bits.
func TestTranslateIPv6FragmentMaximumOffset(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{
		NextHeader: layers.IPProtocolTCP, FragmentOffset: 8191, Identification: 0x1234abcd,
	}
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, []byte("final")), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	translated, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || translated.FragOffset != 8191 || translated.Id != 0xabcd {
		t.Fatalf("unexpected maximum IPv6 fragment translation: %+v", translated)
	}
}

// RFC 7915 Section 5.1.1: a Fragment Header followed by an extension header should be dropped.
func TestTranslateDropsFragmentFollowedByExtensionHeader(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{
		NextHeader: layers.IPProtocolIPv6Destination, Identification: 0x01020304,
	}
	destinationOptions := []byte{byte(layers.IPProtocolTCP), 0, 0, 0, 0, 0, 0, 0}
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, append(destinationOptions, tcpFragmentPayload([]byte("extension"))...)), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("fragment followed by an extension header was translated: err=%v", err)
	}
}

// RFC 7915 Section 5.1.1: a Fragment Header followed by AH must be dropped.
func TestTranslateDropsFragmentFollowedByAuthenticationHeader(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolAH, Identification: 0x01020304}
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 8)), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("fragment followed by AH was translated: err=%v", err)
	}
}

// RFC 7915 Section 5.1.1: known IPv6 extension headers without gopacket layer types are also dropped.
func TestTranslateDropsFragmentFollowedByMobilityHeader(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocol(135), Identification: 0x01020304}
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 8)), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("fragment followed by Mobility Header was translated: err=%v", err)
	}
}

// RFC 7915 Section 5.1.1: ESP is the exception and may follow an IPv6 Fragment Header.
func TestTranslateFragmentFollowedByESP(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
		SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolESP, Identification: 0x01020304}
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, make([]byte, 8)), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if translated.Protocol != layers.IPProtocolESP || translated.FragOffset != 0 {
		t.Fatalf("unexpected ESP fragment translation: %+v", translated)
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

// RFC 7915 Section 4.5 and 1.2: a stateless translator cannot compute the UDP checksum of a fragmented packet,
// so the first fragment of a zero-checksum IPv4 UDP datagram SHOULD be dropped.
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

// RFC 7915 Sections 4.5 and 5.5: with a non-checksum-neutral mapping the transport checksum must be updated,
// which a stateless translator can do for the first fragment because the checksum field is in its header.
func TestTranslateFirstFragmentUpdatesChecksumForNonNeutralMapping(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"}})

	t.Run("IPv4 to IPv6", func(t *testing.T) {
		ip := &layers.IPv4{
			Version: 4, IHL: 5, Id: 0x1234, TTL: defaultTTL, Protocol: layers.IPProtocolTCP,
			Flags: layers.IPv4MoreFragments, SrcIP: ipv4Source, DstIP: ipv4Dest,
		}
		segment := tcpSegment(t, ip, []byte{1, 2, 3, 4}) // 24 octets: a valid multiple of 8 for a non-final fragment
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(segment)), layers.LayerTypeIPv4, gopacket.Default)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return translator.TranslateIPv4(input, siit.TranslationOverrides{})
		})
		packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
		fragment, ok := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
		if !ok {
			t.Fatalf("missing IPv6 fragment: %v", packet.ErrorLayer())
		}
		tcp := gopacket.NewPacket(fragment.Payload, layers.LayerTypeTCP, gopacket.Default).Layer(layers.LayerTypeTCP).(*layers.TCP)
		if want := recalculatedTCPChecksum(t, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), tcp); tcp.Checksum != want {
			t.Fatalf("TCP checksum is %#x, want %#x for the translated pseudo-header", tcp.Checksum, want)
		}
	})
	t.Run("IPv6 to IPv4", func(t *testing.T) {
		ip := &layers.IPv6{
			Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL,
			SrcIP: netIP("2001:db8::10"), DstIP: ipv6Source,
		}
		segment := tcpSegment(t, ip, []byte{1, 2, 3, 4})
		fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, MoreFragments: true, Identification: 0x01020304}
		input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, segment), layers.LayerTypeIPv6, gopacket.Default)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return translator.TranslateIPv6(input, siit.TranslationOverrides{})
		})
		packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
		translated := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcp := gopacket.NewPacket(translated.Payload, layers.LayerTypeTCP, gopacket.Default).Layer(layers.LayerTypeTCP).(*layers.TCP)
		if want := recalculatedTCPChecksum(t, translated, tcp); tcp.Checksum != want {
			t.Fatalf("TCP checksum is %#x, want %#x for the translated pseudo-header", tcp.Checksum, want)
		}
	})
}

// RFC 7915 Section 5.1.1: extension headers before the Fragment Header are skipped; the fragment is translated.
func TestTranslateIPv6HopByHopBeforeFragmentHeader(t *testing.T) {
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6HopByHop, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	hopByHop := []byte{byte(layers.IPProtocolIPv6Fragment), 0, 1, 4, 0, 0, 0, 0}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, MoreFragments: true, Identification: 0x01020304}
	fragmentPayload := tcpFragmentPayload([]byte{0, 1, 2, 3})
	payload := append(append(append([]byte{}, hopByHop...), ipv6FragmentHeader(fragment)...), fragmentPayload...)
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if translated.Protocol != layers.IPProtocolTCP || translated.Flags&layers.IPv4MoreFragments == 0 || translated.Id != 0x0304 ||
		translated.Length != uint16(ipv4HeaderLength+len(fragmentPayload)) || !bytes.Equal(translated.Payload, fragmentPayload) {
		t.Fatalf("fragment behind Hop-by-Hop was not translated correctly: %+v", translated)
	}
}

// RFC 8200 Section 4.5 / RFC 7915 Section 5.1.1: an atomic fragment (offset 0, M=0) is translated as a fragment
// with MF=0 and offset 0, with the Don't Fragment bit cleared and the Identification carried over.
func TestTranslateIPv6AtomicFragment(t *testing.T) {
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolIPv6Fragment, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	fragment := &layers.IPv6Fragment{NextHeader: layers.IPProtocolTCP, Identification: 0x0a0b0c0d}
	fragmentPayload := tcpFragmentPayload([]byte("atom"))
	input := gopacket.NewPacket(serializeIPv6FragmentPacket(t, ip, fragment, fragmentPayload), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if translated.Flags != 0 || translated.FragOffset != 0 || translated.Id != 0x0c0d || !bytes.Equal(translated.Payload, fragmentPayload) {
		t.Fatalf("atomic fragment was not translated as expected: %+v", translated)
	}
}
