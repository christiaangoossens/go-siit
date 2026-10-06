package siit_test

import (
	"bytes"
	"errors"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.1 and 4.5: translate IPv4/TCP headers and recalculate the TCP pseudo-header checksum.
func TestTranslateIPv4ToIPv6TCP(t *testing.T) {
	ipv4Packet := ipv4TCPPacket(t, defaultTTL)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(ipv4Packet, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)

	ipv4Layer := ipv4Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		t.Fatalf("translated packet has no IPv6 layer: %v", packet.ErrorLayer())
	}
	if ip.TrafficClass != ipv4Layer.TOS || ip.FlowLabel != 0 || ip.NextHeader != layers.IPProtocolTCP || ip.HopLimit != 63 {
		t.Fatalf("unexpected IPv6 header: %+v", ip)
	}
	if !ip.SrcIP.Equal(ipv4TranslatedSource) || !ip.DstIP.Equal(ipv4TranslatedDest) {
		t.Fatalf("unexpected IPv6 addresses: %s -> %s", ip.SrcIP, ip.DstIP)
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcp.Checksum == 0 || !bytes.Equal(tcp.Payload, []byte("hello")) {
		t.Fatalf("TCP payload or checksum was not translated as expected: %x", ip.Payload)
	}
	if tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) {
		t.Fatalf("incorrect translated TCP checksum: got %#x", tcp.Checksum)
	}
}

// RFC 7915 Sections 5.1, 5.5, and 6: reverse TCP translation uses RFC 6052 address mapping and checksum recalculation.
func TestTranslateIPv6ToIPv4TCPUsesRFC6052Mapping(t *testing.T) {
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(ipv6TCPPacket(t, defaultTTL), siit.TranslationOverrides{})
	})

	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatalf("translated packet has no IPv4 layer: %v", packet.ErrorLayer())
	}
	if !ip.SrcIP.Equal(ipv6TranslatedSource) || !ip.DstIP.Equal(ipv6TranslatedDest) {
		t.Fatalf("RFC 6052 address mapping failed: %s -> %s", ip.SrcIP, ip.DstIP)
	}
	if ip.TOS != testTrafficClass || ip.TTL != defaultTTL-1 || ip.Protocol != layers.IPProtocolTCP || ip.Flags != 0 {
		t.Fatalf("unexpected IPv4 header: %+v", ip)
	}
	if ip.Length != uint16(len(result)) || ip.Checksum != ipv4HeaderChecksum(ip) {
		t.Fatalf("translated IPv4 length or header checksum is invalid: length=%d checksum=%#x", ip.Length, ip.Checksum)
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcp.Checksum == 0 || !bytes.Equal(tcp.Payload, []byte("hello")) {
		t.Fatalf("TCP payload or checksum was not translated as expected: %v", packet.ErrorLayer())
	}
	expected := recalculatedTCPChecksum(t, ip, tcp)
	if tcp.Checksum != expected {
		t.Fatalf("incorrect translated TCP checksum: got %#x, want %#x", tcp.Checksum, expected)
	}
}

// RFC 7915 Section 5.1: IPv4 packets up to 1260 bytes clear DF; larger packets set DF.
func TestTranslateIPv6ToIPv4SetsDontFragmentAbove1260Bytes(t *testing.T) {
	for _, test := range []struct {
		name       string
		payloadLen int
		wantDF     bool
	}{
		{name: "at threshold", payloadLen: 1260 - ipv4HeaderLength, wantDF: false},
		{name: "above threshold", payloadLen: 1261 - ipv4HeaderLength, wantDF: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv6{
				Version: 6, NextHeader: layers.IPProtocol(47), HopLimit: defaultTTL,
				SrcIP: ipv6Source, DstIP: ipv6Dest,
			}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(bytes.Repeat([]byte{0xab}, test.payloadLen))), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			gotDF := translated.Flags&layers.IPv4DontFragment != 0
			if gotDF != test.wantDF || translated.Length != uint16(20+test.payloadLen) {
				t.Fatalf("unexpected IPv4 size/DF: length=%d DF=%t", translated.Length, gotDF)
			}
		})
	}
}

// RFC 7915 Sections 4.5 and 5.5: translate UDP in both directions, preserve payloads, and recalculate checksums.
func TestTranslateUDPBothDirections(t *testing.T) {
	ipv4 := &layers.IPv4{Version: 4, IHL: 5, TOS: 0x2e, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	udp4 := &layers.UDP{SrcPort: testSourcePort, DstPort: dnsPort}
	if err := udp4.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	input4 := gopacket.NewPacket(serializeTestPacket(t, ipv4, udp4, gopacket.Payload([]byte("dns"))), layers.LayerTypeIPv4, gopacket.Default)
	result6 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input4, siit.TranslationOverrides{})
	})
	packet6 := gopacket.NewPacket(result6, layers.LayerTypeIPv6, gopacket.Default)
	udp6, ok := packet6.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || udp6.Checksum == 0 || !bytes.Equal(udp6.Payload, []byte("dns")) {
		t.Fatalf("UDP was not translated to IPv6: %v", packet6.ErrorLayer())
	}
	if udp6.Checksum == 0 {
		t.Fatal("translated IPv6 UDP checksum is zero")
	}
	ip6 := packet6.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if udp6.Checksum != recalculatedUDPChecksum(t, ip6, udp6) {
		t.Fatalf("translated IPv6 UDP checksum is invalid: %#x", udp6.Checksum)
	}

	result4 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(packet6, siit.TranslationOverrides{})
	})
	packet4 := gopacket.NewPacket(result4, layers.LayerTypeIPv4, gopacket.Default)
	udp4Result, ok := packet4.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || udp4Result.Checksum == 0 || !bytes.Equal(udp4Result.Payload, []byte("dns")) {
		t.Fatalf("UDP was not translated back to IPv4: %v", packet4.ErrorLayer())
	}
	ip4Result := packet4.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if udp4Result.Checksum != recalculatedUDPChecksum(t, ip4Result, udp4Result) {
		t.Fatalf("translated IPv4 UDP checksum is invalid: %#x", udp4Result.Checksum)
	}
}

// RFC 7915 Sections 4.5 and 5.5: TCP payloads of empty, odd, and even lengths retain exact data and checksums.
func TestTranslateTCPPayloadVariants(t *testing.T) {
	for _, payload := range [][]byte{nil, {0x01}, {0x01, 0x02}} {
		input := ipv4TCPPayloadPacket(t, payload, nil)
		translated6 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
		})
		packet6 := gopacket.NewPacket(translated6, layers.LayerTypeIPv6, gopacket.Default)
		tcp6, ok := packet6.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || !bytes.Equal(tcp6.Payload, payload) || tcp6.Checksum == 0 {
			t.Fatalf("TCP payload changed for %x: %v", payload, packet6.ErrorLayer())
		}
		if tcp6.Checksum != recalculatedTCPChecksum(t, packet6.Layer(layers.LayerTypeIPv6).(*layers.IPv6), tcp6) {
			t.Fatalf("TCP checksum changed for %x: got %#x", payload, tcp6.Checksum)
		}
		translated4 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv6(packet6, siit.TranslationOverrides{})
		})
		packet4 := gopacket.NewPacket(translated4, layers.LayerTypeIPv4, gopacket.Default)
		tcp4, ok := packet4.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || !bytes.Equal(tcp4.Payload, payload) || tcp4.Checksum == 0 {
			t.Fatalf("TCP round-trip changed payload for %x: %v", payload, packet4.ErrorLayer())
		}
		if tcp4.Checksum != recalculatedTCPChecksum(t, packet4.Layer(layers.LayerTypeIPv4).(*layers.IPv4), tcp4) {
			t.Fatalf("TCP round-trip checksum changed for %x: got %#x", payload, tcp4.Checksum)
		}
	}
}

// RFC 7915 Sections 4.5 and 5.5: supported TCP options are preserved during translation.
func TestTranslateTCPOptions(t *testing.T) {
	options := []layers.TCPOption{{OptionType: 2, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}}
	input := ipv4TCPPayloadPacket(t, []byte("options"), options)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || len(tcp.Options) != 1 || tcp.Options[0].OptionType != 2 || !bytes.Equal(tcp.Options[0].OptionData, []byte{0x05, 0xb4}) {
		t.Fatalf("TCP options were not preserved: %v", packet.ErrorLayer())
	}
}

// RFC 7915 Sections 4.5 and 5.5: TCP options are preserved in IPv6-to-IPv4 translation.
func TestTranslateTCPOptionsIPv6ToIPv4(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, TrafficClass: testTrafficClass, NextHeader: layers.IPProtocolTCP,
		HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	tcp := &layers.TCP{
		SrcPort: testSourcePort, DstPort: testTCPDestinationPort,
		Seq: testTCPSequence, Ack: testTCPAcknowledgement, SYN: true,
		Window: testTCPWindow, Options: []layers.TCPOption{{OptionType: 2, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload([]byte("options"))), layers.LayerTypeIPv6, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	translated, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || len(translated.Options) != 1 || translated.Options[0].OptionType != 2 || !bytes.Equal(translated.Options[0].OptionData, []byte{0x05, 0xb4}) {
		t.Fatalf("TCP options were not preserved: %v", packet.ErrorLayer())
	}
	if translated.Checksum != recalculatedTCPChecksum(t, packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4), translated) {
		t.Fatalf("translated TCP checksum is invalid: %#x", translated.Checksum)
	}
}

// RFC 7915 Sections 4.5 and 5.5: UDP payloads of empty, odd, and even lengths retain exact data and checksums.
func TestTranslateUDPPayloadVariants(t *testing.T) {
	for _, payload := range [][]byte{nil, {0x01}, {0x01, 0x02}} {
		input := ipv4UDPPacket(t, payload)
		translated6 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
		})
		packet6 := gopacket.NewPacket(translated6, layers.LayerTypeIPv6, gopacket.Default)
		udp6, ok := packet6.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || !bytes.Equal(udp6.Payload, payload) || udp6.Checksum == 0 {
			t.Fatalf("UDP payload/checksum changed for %x: %v", payload, packet6.ErrorLayer())
		}
		if udp6.Checksum != recalculatedUDPChecksum(t, packet6.Layer(layers.LayerTypeIPv6).(*layers.IPv6), udp6) {
			t.Fatalf("UDP checksum changed for %x: got %#x", payload, udp6.Checksum)
		}
		translated4 := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return testTranslator().TranslateIPv6(packet6, siit.TranslationOverrides{})
		})
		packet4 := gopacket.NewPacket(translated4, layers.LayerTypeIPv4, gopacket.Default)
		udp4, ok := packet4.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || !bytes.Equal(udp4.Payload, payload) || udp4.Checksum == 0 {
			t.Fatalf("UDP round-trip changed for %x: %v", payload, packet4.ErrorLayer())
		}
		if udp4.Checksum != recalculatedUDPChecksum(t, packet4.Layer(layers.LayerTypeIPv4).(*layers.IPv4), udp4) {
			t.Fatalf("UDP round-trip checksum changed for %x: got %#x", payload, udp4.Checksum)
		}
	}
}

// Local API contract: PreventTTLDecrement preserves the input TTL or Hop Limit in either direction.
func TestTranslateCanPreserveTTLAndHopLimit(t *testing.T) {
	ipv4Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(ipv4TCPPacket(t, 37), siit.TranslationOverrides{QuotedPacket: true})
	})
	if got := gopacket.NewPacket(ipv4Result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6).HopLimit; got != 37 {
		t.Fatalf("IPv4 TTL was decremented despite override: %d", got)
	}

	ipv6Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(ipv6TCPPacket(t, 37), siit.TranslationOverrides{QuotedPacket: true})
	})
	if got := gopacket.NewPacket(ipv6Result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4).TTL; got != 37 {
		t.Fatalf("IPv6 Hop Limit was decremented despite override: %d", got)
	}
}

// Local packet-size contract: a 1260-byte unfragmented IPv4 packet fits the default 1280-byte IPv6 MTU.
func TestTranslateAtMaximumSupportedIPv4Size(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, maxIPv4PacketLength-ipv4HeaderLength-udpHeaderLength)
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	if len(result) != maxIPv6PacketLength {
		t.Fatalf("maximum-size IPv4 packet translated to %d bytes, want %d", len(result), maxIPv6PacketLength)
	}
	translated := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	if translated.ErrorLayer() != nil {
		t.Fatalf("maximum-size translated packet is invalid: %v", translated.ErrorLayer())
	}
}

// Local packet-size contract: a fragmented IPv4 packet reserves eight more bytes for the IPv6 Fragment header.
func TestTranslateAtMaximumSupportedFragmentedIPv4Size(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, maxFragmentedIPv4Length-ipv4HeaderLength)
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP,
		Flags: layers.IPv4MoreFragments, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	if len(result) != maxIPv6PacketLength {
		t.Fatalf("maximum-size fragmented IPv4 packet translated to %d bytes, want %d", len(result), maxIPv6PacketLength)
	}
}

// Local packet-size contract: unfragmented IPv4 packets larger than 1260 bytes are rejected by the default MTU.
func TestTranslateRejectsOversizedIPv4Packet(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, maxIPv4PacketLength+1-ipv4HeaderLength-udpHeaderLength)
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	input := gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
	result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	if err == nil || result.Packet != nil {
		t.Fatalf("oversized IPv4 packet was not rejected: result length=%d err=%v", len(result.Packet), err)
	}
}

// Local packet-size contract: nothing is ever fragmented, so with a 1500-byte IPv6 MTU a packet that does not
// fit (1481 bytes unfragmented, 1473 bytes already fragmented) is rejected with ErrPacketOversized, never
// truncated, forwarded, or fragmented.
func TestTranslateUsesConfiguredMTU(t *testing.T) {
	for _, test := range []struct {
		name       string
		packetSize int
		fragmented bool
		wantError  bool
	}{
		{name: "maximum packet", packetSize: 1480},
		{name: "oversized packet", packetSize: 1481, wantError: true},
		{name: "maximum fragment", packetSize: 1472, fragmented: true},
		{name: "oversized fragment", packetSize: 1473, fragmented: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest}
			var input gopacket.Packet
			if test.fragmented {
				ip.Flags = layers.IPv4MoreFragments
				input = gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(bytes.Repeat([]byte{0xab}, test.packetSize-ipv4HeaderLength))), layers.LayerTypeIPv4, gopacket.Default)
			} else {
				udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
				if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte{0xab}, test.packetSize-ipv4HeaderLength-udpHeaderLength)
				input = gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
			}
			result, err := translatorWithMTU(t, 1500).TranslateIPv4(input, siit.TranslationOverrides{})
			if test.wantError {
				if !errors.Is(err, siit.ErrPacketOversized) || result.Packet != nil {
					t.Fatalf("oversized IPv4 packet was not rejected with ErrPacketOversized: result length=%d err=%v", len(result.Packet), err)
				}
				return
			}
			if err != nil || len(result.Packet) != test.packetSize+ipv6HeaderLength-ipv4HeaderLength+boolToInt(test.fragmented)*8 {
				t.Fatalf("maximum IPv4 packet was not translated to a full-size IPv6 packet: result length=%d err=%v", len(result.Packet), err)
			}
		})
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestNewTranslatorWithMTURejectsValuesBelowIPv6Minimum(t *testing.T) {
	_, nat64Net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := siit.NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, nil, 1279); err == nil {
		t.Fatal("translator accepted an MTU below the IPv6 minimum")
	}
}
