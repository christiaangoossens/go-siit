package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.5 and 5.5: transport checksums must follow both checksum-neutral and non-neutral address mappings.
func TestTransportChecksumsFollowNeutralAndNonNeutralMappings(t *testing.T) {
	input := ipv4TCPPacket(t, defaultTTL)
	cases := []struct {
		name        string
		source      []byte
		destination []byte
	}{
		{
			name:        "checksum-neutral default mapping",
			source:      ipv4TranslatedSource,
			destination: ipv4TranslatedDest,
		},
		{
			name:        "non-neutral address override",
			source:      netIP("2001:db8::10"),
			destination: netIP("2001:db8::20"),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			translator := testTranslator()
			if test.name == "non-neutral address override" {
				translator = testTranslatorWithEAM(siit.RawEAMTable{
					{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
					{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::20/128"},
				})
			}
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				translated, err := translator.TranslateIPv4(input, siit.TranslationOverrides{})
				return translated, err
			})
			packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
			ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) {
				t.Fatalf("checksum does not match mapped pseudo-header: %#x", tcp.Checksum)
			}
		})
	}
}

// RFC 7915 Sections 4.5 and 5.5: UDP checksums must cover the translated pseudo-header.
func TestUDPChecksumFollowsNonNeutralAddressMapping(t *testing.T) {
	input := ipv4UDPPacket(t, []byte("dns"))
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
		{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::20/128"},
	})
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		t.Fatalf("translated packet has no UDP layer: %v", packet.ErrorLayer())
	}
	if udp.Checksum != recalculatedUDPChecksum(t, ip, udp) {
		t.Fatalf("UDP checksum does not match the non-neutral pseudo-header: %#x", udp.Checksum)
	}
}

// RFC 7915 Sections 4.2 and 5.2: ICMP checksums must cover the translated ICMP pseudo-header.
func TestICMPChecksumFollowsNonNeutralAddressMapping(t *testing.T) {
	input := ipv4ICMPPacket(t, echoRequest, 0, []byte("icmp"))
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
		{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::20/128"},
	})
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok {
		t.Fatalf("translated packet has no ICMPv6 layer: %v", packet.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
		t.Fatalf("ICMP checksum does not match the non-neutral pseudo-header: %#x", icmp.Checksum)
	}
}

// RFC 7915 Section 5.5 and RFC 8200 Section 8.1: IPv6 UDP packets with a zero checksum are silently dropped.
func TestTranslateIPv6ZeroChecksumUDPDropsPacket(t *testing.T) {
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: ipv6Source, DstIP: ipv6Dest}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 9999}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	packetBytes := serializeTestPacket(t, ip, udp, gopacket.Payload([]byte("dns")))
	checksumOffset := udpChecksumOffset(ipv6HeaderLength)
	packetBytes[checksumOffset] = 0
	packetBytes[checksumOffset+1] = 0
	input := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if err != nil || result.Packet != nil {
		t.Fatalf("IPv6 UDP with a zero checksum was not silently dropped: result length=%d err=%v", len(result.Packet), err)
	}
}

// RFC 7915 Sections 5 and 5.5: IPv6 transport checksums must be evaluated before translation.
func TestTranslateIPv6RejectsInvalidTransportChecksums(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		checksumOffset int
	}{
		{name: "TCP", packet: ipv6TCPPacket(t, defaultTTL).Data(), checksumOffset: ipv6HeaderLength + 16},
		{name: "ICMPv6", packet: ipv6ICMPEchoChecksumPacket(t).Data(), checksumOffset: ipv6HeaderLength + 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packetBytes := append([]byte(nil), test.packet...)
			binary.BigEndian.PutUint16(packetBytes[test.checksumOffset:test.checksumOffset+2], 0)
			input := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.Default)
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			if result.Packet != nil {
				t.Fatalf("IPv6 packet with an invalid %s checksum was translated: err=%v", test.name, err)
			}
			if !result.SrcIP.Equal(ipv6TranslatedSource) || !result.DstIP.Equal(ipv6TranslatedDest) {
				t.Fatalf("IPv6 packet metadata was not preserved for invalid %s checksum: %s -> %s", test.name, result.SrcIP, result.DstIP)
			}
		})
	}
}

func ipv6ICMPEchoChecksumPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	echo := &layers.ICMPv6Echo{Identifier: 1, SeqNumber: 1}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, echo, gopacket.Payload([]byte("icmp"))), layers.LayerTypeIPv6, gopacket.Default)
}

// Local robustness: invalid IPv4 header and transport checksums must not be translated.
func TestTranslateRejectsInvalidIPv4Checksums(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		checksumOffset int
	}{
		{name: "IPv4 header", packet: ipv4TCPPacket(t, defaultTTL).Data(), checksumOffset: ipv4ChecksumOffset},
		{name: "TCP", packet: ipv4TCPPacket(t, defaultTTL).Data(), checksumOffset: ipv4HeaderLength + transportChecksumOffset},
		{name: "ICMPv4", packet: ipv4ICMPPacket(t, echoRequest, 0, []byte("icmp")).Data(), checksumOffset: ipv4HeaderLength + icmpChecksumOffset},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packetBytes := append([]byte(nil), test.packet...)
			binary.BigEndian.PutUint16(packetBytes[test.checksumOffset:test.checksumOffset+2], 0)
			input := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)
			result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			if result.Packet != nil {
				t.Fatalf("IPv4 packet with an invalid %s checksum was translated: err=%v", test.name, err)
			}
			if !result.SrcIP.Equal(ipv4TranslatedSource) || !result.DstIP.Equal(ipv4TranslatedDest) {
				t.Fatalf("IPv4 packet metadata was not preserved for invalid %s checksum: %s -> %s", test.name, result.SrcIP, result.DstIP)
			}
		})
	}
}

// RFC 7915 Section 4.5: zero-checksum UDP from IPv4 is either dropped or forwarded with a computed IPv6 checksum.
// The library implements the second option for unfragmented packets.
func TestTranslateIPv4ZeroChecksumUDP(t *testing.T) {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: dnsPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	packetBytes := serializeTestPacket(t, ip, udp, gopacket.Payload([]byte("dns")))
	checksumOffset := udpChecksumOffset(ipv4HeaderLength)
	packetBytes[checksumOffset] = 0
	packetBytes[checksumOffset+1] = 0
	input := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	if err != nil {
		t.Fatalf("zero-checksum UDP returned an error instead of being dropped or forwarded: %v", err)
	}
	if result.Packet == nil {
		return
	}
	packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
	translated, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || translated.Checksum == 0 || translated.Checksum != recalculatedUDPChecksum(t, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6), translated) || !bytes.Equal(translated.Payload, []byte("dns")) {
		t.Fatalf("forwarded zero-checksum UDP must carry a valid IPv6 checksum: %v", packet.ErrorLayer())
	}
}

// RFC 7915 Sections 4.5 and 5.5, RFC 768: a nonzero UDP checksum that does not verify is never translated.
func TestTranslateRejectsInvalidNonzeroUDPChecksum(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		packetBytes := append([]byte{}, ipv4UDPPacket(t, []byte("dns")).Data()...)
		packetBytes[ipv4HeaderLength+6] ^= 0xff
		input := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)
		result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
		if !errors.Is(err, siit.ErrInvalidPacket) || result.Packet != nil {
			t.Fatalf("UDP packet with a bad checksum was not rejected: err=%v", err)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		packetBytes := serializeTestPacket(t, ip, udp, gopacket.Payload([]byte("dns")))
		packetBytes[ipv6HeaderLength+6] ^= 0xff
		input := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.Default)
		result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		if !errors.Is(err, siit.ErrInvalidPacket) || result.Packet != nil {
			t.Fatalf("UDP packet with a bad checksum was not rejected: err=%v", err)
		}
	})
}
