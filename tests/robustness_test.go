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
