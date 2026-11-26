package siit_test

import (
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Benchmarks for the per-packet cost of the translator. Each case runs twice: FromBytes includes decoding the raw
// packet (what a tun reader pays), FromPacket starts from an already decoded packet.
func BenchmarkTranslate(b *testing.B) {
	cases := []struct {
		name      string
		data      []byte
		layerType gopacket.LayerType
		translate func(*siit.Translator, gopacket.Packet) (siit.TranslatedPacket, error)
	}{
		{"TCP IPv4 to IPv6", benchmarkIPv4TCP(b, ipv4Source, ipv4Dest), layers.LayerTypeIPv4, benchmarkTranslateIPv4},
		{"TCP IPv6 to IPv4", benchmarkIPv6TCP(b), layers.LayerTypeIPv6, benchmarkTranslateIPv6},
		{"ICMPv4 error to ICMPv6", benchmarkIPv4ICMPError(b), layers.LayerTypeIPv4, benchmarkTranslateIPv4},
	}

	for _, test := range cases {
		b.Run(test.name+"/FromBytes", func(b *testing.B) {
			translator := testTranslator()
			b.ReportAllocs()

			for b.Loop() {
				packet := gopacket.NewPacket(test.data, test.layerType, gopacket.Default)
				benchmarkRequireTranslated(b, test.translate, translator, packet)
			}
		})

		b.Run(test.name+"/FromPacket", func(b *testing.B) {
			translator := testTranslator()
			packet := gopacket.NewPacket(test.data, test.layerType, gopacket.Default)
			b.ReportAllocs()

			for b.Loop() {
				benchmarkRequireTranslated(b, test.translate, translator, packet)
			}
		})
	}
}

func benchmarkTranslateIPv4(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
	return translator.TranslateIPv4(packet, siit.TranslationOverrides{})
}

func benchmarkTranslateIPv6(translator *siit.Translator, packet gopacket.Packet) (siit.TranslatedPacket, error) {
	return translator.TranslateIPv6(packet, siit.TranslationOverrides{})
}

func benchmarkRequireTranslated(b *testing.B, translate func(*siit.Translator, gopacket.Packet) (siit.TranslatedPacket, error), translator *siit.Translator, packet gopacket.Packet) {
	result, err := translate(translator, packet)
	if err != nil || result.Packet == nil {
		b.Fatalf("benchmark packet was not translated: err=%v", err)
	}
}

func benchmarkSerialize(b *testing.B, packetLayers ...gopacket.SerializableLayer) []byte {
	b.Helper()
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, packetLayers...); err != nil {
		b.Fatal(err)
	}

	return buffer.Bytes()
}

// benchmarkIPv4TCP builds a TCP segment with a 64-octet payload, a typical small packet.
func benchmarkIPv4TCP(b *testing.B, source, destination []byte) []byte {
	b.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolTCP, SrcIP: source, DstIP: destination}
	tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, Seq: testTCPSequence, ACK: true, Window: testTCPWindow}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		b.Fatal(err)
	}

	return benchmarkSerialize(b, ip, tcp, gopacket.Payload(make([]byte, 64)))
}

func benchmarkIPv6TCP(b *testing.B) []byte {
	b.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolTCP, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, Seq: testTCPSequence, ACK: true, Window: testTCPWindow}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		b.Fatal(err)
	}

	return benchmarkSerialize(b, ip, tcp, gopacket.Payload(make([]byte, 64)))
}

// benchmarkIPv4ICMPError builds a Port Unreachable that travels back along the path of the quoted TCP segment,
// so it exercises the translation of the quoted packet.
func benchmarkIPv4ICMPError(b *testing.B) []byte {
	b.Helper()
	quote := benchmarkIPv4TCP(b, ipv4Source, ipv4Dest)
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Dest, DstIP: ipv4Source}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}

	return benchmarkSerialize(b, ip, icmp, gopacket.Payload(quote))
}
