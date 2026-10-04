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

// Local robustness: truncated IPv4 and IPv6 headers must be rejected without panics.
func TestTranslateRejectsTruncatedIPHeaders(t *testing.T) {
	tests := []struct {
		name      string
		layer     gopacket.LayerType
		payload   []byte
		translate func(*siit.Translator, gopacket.Packet) (siit.TranslatedPacket, error)
	}{
		{name: "IPv4", layer: layers.LayerTypeIPv4, payload: []byte{0x45, 0, 0, 20}, translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
			return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
		}},
		{name: "IPv6", layer: layers.LayerTypeIPv6, payload: []byte{0x60, 0, 0, 0}, translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
			return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := gopacket.NewPacket(test.payload, test.layer, gopacket.Default)
			if _, err := test.translate(testTranslator(), input); err == nil {
				t.Fatal("truncated IP header was accepted")
			}
		})
	}
}

// RFC 6052 Section 2 and RFC 7915 Section 6: a global IPv4 address is embedded in the /96 prefix.
func TestRFC6052MappingGlobalAddress(t *testing.T) {
	ipv4 := net.ParseIP("8.8.8.8").To4()
	input := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	want := net.ParseIP("64:ff9b::808:808")
	if !ip.SrcIP.Equal(want) || !ip.DstIP.Equal(want) {
		t.Fatalf("mapped %s to %s -> %s, want %s", ipv4, ip.SrcIP, ip.DstIP, want)
	}
}

// RFC 7915 Sections 5.1 and 6: an IPv6 destination outside the configured translation prefix is not mappable.
func TestTranslateIPv6RejectsUnmappableDestination(t *testing.T) {
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolTCP, HopLimit: 64, SrcIP: ipv6Source, DstIP: net.ParseIP("2001:db8::2")}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 20))), layers.LayerTypeIPv6, gopacket.Default)
	if _, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{}); err == nil {
		t.Fatal("IPv6 destination outside the NAT64 prefix was translated")
	}
}

// Local robustness: truncated TCP, UDP, and ICMP payloads must return errors without panics.
func TestTranslateMalformedTransportAndICMPReturnsErrors(t *testing.T) {
	tests := []struct {
		name     string
		protocol layers.IPProtocol
	}{
		{name: "TCP", protocol: layers.IPProtocolTCP},
		{name: "UDP", protocol: layers.IPProtocolUDP},
		{name: "ICMP", protocol: layers.IPProtocolICMPv4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: test.protocol, SrcIP: ipv4Source, DstIP: ipv4Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload([]byte{1, 2, 3})), layers.LayerTypeIPv4, gopacket.Default)
			if _, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{}); err == nil {
				t.Fatal("malformed payload was accepted")
			}
		})
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
			if !result.SrcIP.Equal(ipv4RouterAddress) || !result.DstIP.Equal(ipv6TranslatedDest) {
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

// RFC 7915 Sections 4.5 and 5.5: truncated IPv6 TCP, UDP, and ICMP payloads must return errors without panics.
func TestTranslateMalformedIPv6TransportAndICMPReturnsErrors(t *testing.T) {
	tests := []struct {
		name     string
		protocol layers.IPProtocol
	}{
		{name: "TCP", protocol: layers.IPProtocolTCP},
		{name: "UDP", protocol: layers.IPProtocolUDP},
		{name: "ICMPv6", protocol: layers.IPProtocolICMPv6},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv6{
				Version: 6, NextHeader: test.protocol, HopLimit: defaultTTL,
				SrcIP: ipv6Dest, DstIP: ipv6Source,
			}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload([]byte{1, 2, 3})), layers.LayerTypeIPv6, gopacket.Default)
			if _, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{}); err == nil {
				t.Fatal("malformed payload was accepted")
			}
		})
	}
}

// Local API contract: exported sentinel errors classify invalid input and unsupported protocols.
func TestTranslateReturnsSpecificErrors(t *testing.T) {
	noIPv4 := gopacket.NewPacket([]byte{0}, gopacket.LayerTypePayload, gopacket.Default)
	if _, err := testTranslator().TranslateIPv4(noIPv4, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrInvalidPacket) {
		t.Fatalf("missing IPv4 layer returned %v, want ErrInvalidPacket", err)
	}

	noIPv6 := gopacket.NewPacket([]byte{0}, gopacket.LayerTypePayload, gopacket.Default)
	if _, err := testTranslator().TranslateIPv6(noIPv6, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrInvalidPacket) {
		t.Fatalf("missing IPv6 layer returned %v, want ErrInvalidPacket", err)
	}

	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocol(47), SrcIP: ipv4Source, DstIP: ipv4Dest}
	unsupported := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload([]byte("gre"))), layers.LayerTypeIPv4, gopacket.Default)
	if _, err := testTranslator().TranslateIPv4(unsupported, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrUnsupportedProtocol) {
		t.Fatalf("unsupported protocol returned %v, want ErrUnsupportedProtocol", err)
	}
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

// RFC 7915 Sections 4.1 and 5.1: zero and one TTL/Hop Limit values generate complete Time Exceeded errors.
func TestTranslateExpiredTTLBoundaries(t *testing.T) {
	for _, ttl := range []uint8{0, 1} {
		t.Run("IPv4 TTL "+fmt.Sprint(ttl), func(t *testing.T) {
			result, err := testTranslator().TranslateIPv4(ipv4TCPPacket(t, ttl), siit.TranslationOverrides{})
			if !errors.Is(err, siit.ErrTimeExceeded) {
				t.Fatalf("got error %v, want ErrTimeExceeded", err)
			}
			translationErr, ok := err.(*siit.TranslationError)
			if !ok || !bytes.Equal(translationErr.Packet, result.Packet) {
				t.Fatalf("TranslationError.Packet does not match returned packet: %T", err)
			}
			packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || ip.NextHeader != layers.IPProtocolICMPv6 {
				t.Fatalf("missing generated IPv6 ICMP error: %v", packet.ErrorLayer())
			}
			icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
			if !ok || icmp.TypeCode != layers.CreateICMPv6TypeCode(3, 0) || icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
				t.Fatalf("invalid generated IPv6 Time Exceeded: %v", packet.ErrorLayer())
			}
			quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv6, gopacket.Default)
			quotedIP, ok := quoted.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || quotedIP.HopLimit != ttl {
				t.Fatalf("generated quote has Hop Limit %d, want %d", quotedIP.HopLimit, ttl)
			}
		})

		t.Run("IPv6 Hop Limit "+fmt.Sprint(ttl), func(t *testing.T) {
			result, err := testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, ttl, ipv6Dest, ipv6Source), siit.TranslationOverrides{})
			if !errors.Is(err, siit.ErrTimeExceeded) {
				t.Fatalf("got error %v, want ErrTimeExceeded", err)
			}
			translationErr, ok := err.(*siit.TranslationError)
			if !ok || !bytes.Equal(translationErr.Packet, result.Packet) {
				t.Fatalf("TranslationError.Packet does not match returned packet: %T", err)
			}
			packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv4, gopacket.Default)
			ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ip.Protocol != layers.IPProtocolICMPv4 || ip.Checksum != ipv4HeaderChecksum(ip) {
				t.Fatalf("invalid generated IPv4 ICMP error: %v", packet.ErrorLayer())
			}
			icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || icmp.TypeCode != layers.CreateICMPv4TypeCode(11, 0) || icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
				t.Fatalf("invalid generated IPv4 Time Exceeded: %v", packet.ErrorLayer())
			}
			quoted := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
			quotedIP, ok := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || quotedIP.TTL != ttl {
				t.Fatalf("generated quote has TTL %d, want %d", quotedIP.TTL, ttl)
			}
		})
	}
}

// RFC 7915 Section 4.5: zero-checksum UDP from IPv4 may be dropped or forwarded only with a computed IPv6 checksum.
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
	if err != nil || result.Packet == nil {
		return
	}
	packet := gopacket.NewPacket(result.Packet, layers.LayerTypeIPv6, gopacket.Default)
	translated, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || translated.Checksum == 0 {
		t.Fatalf("forwarded zero-checksum UDP must have an IPv6 checksum: %v", packet.ErrorLayer())
	}
}
