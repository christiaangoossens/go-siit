package siit_test

import (
	"bytes"
	"errors"
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
			if _, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrInvalidPacket) {
				t.Fatalf("malformed payload returned %v, want ErrInvalidPacket", err)
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

	// Fragmented ICMPv4 is the one case where an otherwise valid packet is reported as an unsupported protocol.
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Flags: layers.IPv4MoreFragments, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	unsupported := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 8))), layers.LayerTypeIPv4, gopacket.Default)
	if _, err := testTranslator().TranslateIPv4(unsupported, siit.TranslationOverrides{}); !errors.Is(err, siit.ErrUnsupportedProtocol) {
		t.Fatalf("fragmented ICMPv4 returned %v, want ErrUnsupportedProtocol", err)
	}
}

// RFC 7915 Section 4.5 / 5.5: "translators MUST forward all transport protocols", including payloads too short
// to contain a recognizable header.
func TestTranslateForwardsShortUnsupportedProtocolPayloads(t *testing.T) {
	payload := []byte("gre")
	t.Run("IPv4 to IPv6", func(t *testing.T) {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolGRE, SrcIP: ipv4Source, DstIP: ipv4Dest}
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
		})
		translated := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if translated.NextHeader != layers.IPProtocolGRE || !bytes.Equal(translated.Payload, payload) {
			t.Fatalf("short GRE payload was not forwarded unchanged: %+v", translated)
		}
	})
	t.Run("IPv6 to IPv4", func(t *testing.T) {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolGRE, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
		input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		})
		translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if translated.Protocol != layers.IPProtocolGRE || !bytes.Equal(translated.Payload, payload) {
			t.Fatalf("short GRE payload was not forwarded unchanged: %+v", translated)
		}
	})
}

// RFC 7915 Sections 4.5 and 5.5: transport protocols other than TCP, UDP, and ICMP are forwarded unchanged.
func TestTranslateForwardsUnsupportedProtocols(t *testing.T) {
	payload := []byte{0, 1, 2, 3}
	tests := []struct {
		name        string
		packet      gopacket.Packet
		translate   func(*siit.Translator, gopacket.Packet) (siit.TranslatedPacket, error)
		outputLayer gopacket.LayerType
		protocol    layers.IPProtocol
	}{
		{
			name:        "IPv4 GRE",
			outputLayer: layers.LayerTypeIPv6,
			protocol:    layers.IPProtocolGRE,
			packet: func() gopacket.Packet {
				ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolGRE, SrcIP: ipv4Source, DstIP: ipv4Dest}
				return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
			}(),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:        "IPv6 GRE",
			outputLayer: layers.LayerTypeIPv4,
			protocol:    layers.IPProtocolGRE,
			packet: func() gopacket.Packet {
				ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolGRE, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
				return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
			}(),
			translate: func(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return test.translate(testTranslator(), test.packet)
			})
			packet := gopacket.NewPacket(result, test.outputLayer, gopacket.Default)
			if packet.ErrorLayer() != nil {
				t.Fatalf("forwarded protocol produced an invalid packet: %v", packet.ErrorLayer())
			}
			if test.outputLayer == layers.LayerTypeIPv4 {
				ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if ip.Protocol != test.protocol {
					t.Fatalf("got IPv4 protocol %d, want %d", ip.Protocol, test.protocol)
				}
				if !bytes.Equal(ip.Payload, payload) {
					t.Fatalf("forwarded payload changed: %v", ip.Payload)
				}
			} else {
				ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				if ip.NextHeader != test.protocol {
					t.Fatalf("got IPv6 Next Header %d, want %d", ip.NextHeader, test.protocol)
				}
				if !bytes.Equal(ip.Payload, payload) {
					t.Fatalf("forwarded payload changed: %v", ip.Payload)
				}
			}
		})
	}
}
