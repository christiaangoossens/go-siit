package siit_test

import (
	"bytes"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.5 and 5.5: transport protocols other than TCP, UDP, and ICMP are forwarded unchanged.
func TestTranslateForwardsUnsupportedProtocols(t *testing.T) {
	payload := []byte{0, 1, 2, 3}
	tests := []struct {
		name        string
		packet      gopacket.Packet
		translate   func(*siit.Translator, gopacket.Packet) ([]byte, error)
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
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
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
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:        "IPv4 DCCP",
			outputLayer: layers.LayerTypeIPv6,
			protocol:    layers.IPProtocol(33),
			packet: func() gopacket.Packet {
				ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocol(33), SrcIP: ipv4Source, DstIP: ipv4Dest}
				return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
			}(),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
			},
		},
		{
			name:        "IPv6 DCCP",
			outputLayer: layers.LayerTypeIPv4,
			protocol:    layers.IPProtocol(33),
			packet: func() gopacket.Packet {
				ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocol(33), HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
				return gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
			}(),
			translate: func(translator *siit.Translator, packet gopacket.Packet) ([]byte, error) {
				return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mustTranslate(t, func() ([]byte, error) {
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

// Local packet-size contract: a 1280-byte IPv6 packet becomes a 1260-byte IPv4 packet without fragmentation.
func TestTranslateAtMaximumSupportedIPv6Size(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, maxIPv6PacketLength-ipv6HeaderLength-udpHeaderLength)
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() ([]byte, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	if len(result) != maxIPv4PacketLength {
		t.Fatalf("maximum-size IPv6 packet translated to %d bytes, want %d", len(result), maxIPv4PacketLength)
	}
	translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	ipv4, ok := translated.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || ipv4.Length != uint16(len(result)) || ipv4.Checksum != ipv4HeaderChecksum(ipv4) {
		t.Fatalf("maximum-size IPv6 translation has invalid IPv4 header: %v", translated.ErrorLayer())
	}
}

// Local packet-size contract: IPv6 packets larger than 1280 bytes are rejected.
func TestTranslateRejectsOversizedIPv6Packet(t *testing.T) {
	payloadLength := maxIPv6PacketLength + 1 - ipv6HeaderLength - udpHeaderLength
	payload := bytes.Repeat([]byte{0x5a}, payloadLength)
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if err == nil || result != nil {
		t.Fatalf("oversized IPv6 packet was not rejected: result length=%d err=%v", len(result), err)
	}
}
