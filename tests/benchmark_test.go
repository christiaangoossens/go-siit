package siit_test

import (
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Benchmarks for the per-packet cost of the translator. Each case runs twice: FromBytes starts from the raw packet
// (what a tun reader has), FromLayer from a layer the caller already decoded with gopacket.
func BenchmarkTranslate(b *testing.B) {
	cases := []struct {
		name      string
		data      []byte
		layerType gopacket.LayerType
	}{
		{"TCP IPv4 to IPv6", benchmarkIPv4TCP(b, ipv4Source, ipv4Dest), layers.LayerTypeIPv4},
		{"TCP IPv6 to IPv4", benchmarkIPv6TCP(b), layers.LayerTypeIPv6},
		{"ICMPv4 error to ICMPv6", benchmarkIPv4ICMPError(b), layers.LayerTypeIPv4},
	}

	for _, test := range cases {
		b.Run(test.name+"/FromBytes", func(b *testing.B) {
			translator := testTranslator()
			translate := translator.TranslateIPv4
			if test.layerType == layers.LayerTypeIPv6 {
				translate = translator.TranslateIPv6
			}
			b.ReportAllocs()

			for b.Loop() {
				result, err := translate(test.data)
				benchmarkRequireTranslated(b, result, err)
			}
		})

		b.Run(test.name+"/FromLayer", func(b *testing.B) {
			translator := testTranslator()
			packet := gopacket.NewPacket(test.data, test.layerType, gopacket.Default)
			b.ReportAllocs()

			for b.Loop() {
				var result siit.Packet
				var err error
				if ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
					result, err = translator.TranslateIPv4Layer(ip)
				} else {
					result, err = translator.TranslateIPv6Layer(packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6))
				}
				benchmarkRequireTranslated(b, result, err)
			}
		})
	}
}

func benchmarkRequireTranslated(b *testing.B, result siit.Packet, err error) {
	if err != nil || len(result) == 0 {
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
