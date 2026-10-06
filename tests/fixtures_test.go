package siit_test

import (
	"encoding/binary"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	ipv4Source           = net.ParseIP("1.1.1.1").To4()
	ipv4Dest             = net.ParseIP("2.2.2.2").To4()
	ipv4TranslatedSource = net.ParseIP("64:ff9b::101:101").To16()
	ipv4TranslatedDest   = net.ParseIP("64:ff9b::202:202").To16()
	// Both IPv6 endpoints are inside the RFC 6052 prefix so that plain traffic is mappable in both directions.
	ipv6Source           = net.ParseIP("64:ff9b::808:808")
	ipv6Dest             = net.ParseIP("64:ff9b::101:101")
	ipv6TranslatedSource = net.ParseIP("8.8.8.8")
	ipv6TranslatedDest   = net.ParseIP("1.1.1.1")
	// A globally routable router address: RFC 6052 Section 3.1 forbids mapping non-global IPv4 addresses
	// into the Well-Known Prefix, so the router address must be global for generated errors to be valid.
	ipv4RouterAddress = net.ParseIP("9.9.9.9")
	// An IPv6 address outside the NAT64 prefix with no EAM entry: it has no stateless IPv4 mapping.
	ipv6Unmappable = net.ParseIP("2001:db8::1")
)

const (
	ipv4HeaderLength        = 20
	ipv6HeaderLength        = 40
	udpHeaderLength         = 8
	icmpErrorRestHeaderSize = 4
	ipv4TOSOffset           = 1
	ipv4TTLOffset           = 8
	ipv4ChecksumOffset      = 10
	ipv6HopLimitOffset      = 7
	icmpChecksumOffset      = 2
	maxIPv4PacketLength     = 1260
	maxIPv6PacketLength     = 1280
	defaultTTL              = 64
	testSourcePort          = 40000
	testTCPDestinationPort  = 443
	testUDPDestinationPort  = 9999
	dnsPort                 = 53
	testTrafficClass        = 0x2e
	testTCPSequence         = 0x01020304
	testTCPAcknowledgement  = 0x05060708
	testTCPWindow           = 65535
	echoRequest             = 8
	echoReply               = 0
	icmpv4TimeExceeded      = 11
	icmpv6TimeExceeded      = 3
	icmpv6DestUnreachable   = 1
)

func translatorWithPrefix(t *testing.T, prefix string, eamTable siit.RawEAMTable) *siit.Translator {
	t.Helper()
	_, nat64Net, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatal(err)
	}
	translator, err := siit.NewTranslator(nat64Net, ipv4RouterAddress, eamTable)
	if err != nil {
		t.Fatal(err)
	}
	return translator
}

func testTranslator() *siit.Translator {
	return testTranslatorWithEAM(nil)
}

func testTranslatorWithEAM(eamTable siit.RawEAMTable) *siit.Translator {
	_, nat64Net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		panic(err)
	}

	translator, err := siit.NewTranslator(nat64Net, ipv4RouterAddress, eamTable)
	if err != nil {
		panic(err)
	}

	return translator
}

func expectedMappedAddress(address net.IP) net.IP {
	mapped := net.ParseIP("64:ff9b::").To16()
	copy(mapped[12:], address.To4())
	return mapped
}

func serializeTestPacket(t *testing.T, packetLayers ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, packetLayers...)
	if err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return buffer.Bytes()
}

func udpChecksumOffset(networkHeaderLength int) int {
	return networkHeaderLength + 6
}

func ipv4HeaderChecksum(ip *layers.IPv4) uint16 {
	header := append([]byte(nil), ip.Contents...)
	header[ipv4ChecksumOffset], header[ipv4ChecksumOffset+1] = 0, 0
	return checksum(header)
}

// checksum is the RFC 1071 Internet checksum of data.
func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func mustTranslate(t *testing.T, translate func() (siit.TranslatedPacket, error)) []byte {
	t.Helper()
	packet, err := translate()
	if err != nil {
		t.Fatalf("translation failed: %v", err)
	}
	return packet.Packet
}

func requireDropped(t *testing.T, result siit.TranslatedPacket, err error) {
	t.Helper()
	if err != nil || result.Packet != nil {
		t.Fatalf("packet was not silently dropped: result length=%d err=%v", len(result.Packet), err)
	}
}

func requireRejected(t *testing.T, result siit.TranslatedPacket, err error) {
	t.Helper()
	if err == nil || result.Packet != nil {
		t.Fatalf("packet was not rejected: result length=%d err=%v", len(result.Packet), err)
	}
}

func recalculatedTCPChecksum(t *testing.T, ip gopacket.NetworkLayer, tcp *layers.TCP) uint16 {
	t.Helper()
	copyTCP := *tcp
	copyTCP.Checksum = 0
	if err := copyTCP.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(serializeTestPacket(t, &copyTCP, gopacket.Payload(copyTCP.Payload)), layers.LayerTypeTCP, gopacket.Default)
	return packet.Layer(layers.LayerTypeTCP).(*layers.TCP).Checksum
}

func recalculatedUDPChecksum(t *testing.T, ip gopacket.NetworkLayer, udp *layers.UDP) uint16 {
	t.Helper()
	copyUDP := *udp
	copyUDP.Checksum = 0
	if err := copyUDP.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(serializeTestPacket(t, &copyUDP, gopacket.Payload(copyUDP.Payload)), layers.LayerTypeUDP, gopacket.Default)
	return packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Checksum
}

func recalculatedICMPv4Checksum(t *testing.T, icmp *layers.ICMPv4) uint16 {
	t.Helper()
	copyICMP := *icmp
	copyICMP.Checksum = 0
	packet := gopacket.NewPacket(serializeTestPacket(t, &copyICMP, gopacket.Payload(copyICMP.Payload)), layers.LayerTypeICMPv4, gopacket.Default)
	return packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4).Checksum
}

func recalculatedICMPv6Checksum(t *testing.T, ip gopacket.NetworkLayer, icmp *layers.ICMPv6) uint16 {
	t.Helper()
	copyICMP := *icmp
	copyICMP.Checksum = 0
	if err := copyICMP.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(serializeTestPacket(t, &copyICMP, gopacket.Payload(copyICMP.Payload)), layers.LayerTypeICMPv6, gopacket.Default)
	return packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6).Checksum
}

func ipv4TCPPacket(t *testing.T, ttl uint8) gopacket.Packet {
	return ipv4TCPPacketWithAddresses(t, ttl, ipv4Source, ipv4Dest)
}

func ipv4TCPPacketWithAddresses(t *testing.T, ttl uint8, source, destination net.IP) gopacket.Packet {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TOS: testTrafficClass, Id: 0x1234, TTL: ttl,
		Protocol: layers.IPProtocolTCP, SrcIP: source, DstIP: destination,
	}
	tcp := &layers.TCP{
		SrcPort: testSourcePort, DstPort: testTCPDestinationPort,
		Seq: testTCPSequence, Ack: testTCPAcknowledgement, SYN: true,
		Window: testTCPWindow, DataOffset: 5,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload([]byte("hello"))), layers.LayerTypeIPv4, gopacket.Default)
}

func ipv6TCPPacket(t *testing.T, hopLimit uint8) gopacket.Packet {
	return ipv6TCPPacketWithAddresses(t, hopLimit, ipv6Source, ipv6Dest)
}

func ipv4TCPPayloadPacket(t *testing.T, payload []byte, options []layers.TCPOption) gopacket.Packet {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TOS: testTrafficClass, TTL: defaultTTL,
		Protocol: layers.IPProtocolTCP, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	tcp := &layers.TCP{
		SrcPort: testSourcePort, DstPort: testTCPDestinationPort,
		Seq: testTCPSequence, Ack: testTCPAcknowledgement,
		ACK: true, Window: testTCPWindow, Options: options,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

func ipv6TCPPacketWithAddresses(t *testing.T, hopLimit uint8, source, destination net.IP) gopacket.Packet {
	ip := &layers.IPv6{
		Version: 6, TrafficClass: testTrafficClass, NextHeader: layers.IPProtocolTCP,
		HopLimit: hopLimit, SrcIP: source, DstIP: destination,
	}
	tcp := &layers.TCP{
		SrcPort: testSourcePort, DstPort: testTCPDestinationPort,
		Seq: testTCPSequence, Ack: testTCPAcknowledgement,
		SYN: true, Window: testTCPWindow, DataOffset: 5,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload([]byte("hello"))), layers.LayerTypeIPv6, gopacket.Default)
}

func ipv4UDPPacket(t *testing.T, payload []byte) gopacket.Packet {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TOS: testTrafficClass, TTL: defaultTTL,
		Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest,
	}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

// ipv4ICMPPacketWithRest builds an ICMPv4 message whose second header word (Identifier/Sequence) is set.
// For RFC 4884 errors octet 4 is the Parameter Problem pointer and octet 5 is the original datagram length.
func ipv4ICMPPacketWithRest(t *testing.T, messageType, code uint8, id, seq uint16, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Dest, DstIP: ipv4Source}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(messageType, code), Id: id, Seq: seq}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

// ipv6ICMPErrorPacket builds an ICMPv6 error with explicit addresses and the mandatory four-byte
// type-specific word (RFC 4443 Sections 3.1-3.4) in front of the quoted packet.
func ipv6ICMPErrorPacket(t *testing.T, src, dst net.IP, messageType, code uint8, rest, quoted []byte) gopacket.Packet {
	t.Helper()
	if len(rest) != icmpErrorRestHeaderSize {
		t.Fatalf("ICMPv6 rest header must be %d bytes, got %d", icmpErrorRestHeaderSize, len(rest))
	}
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: src, DstIP: dst}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(messageType, code)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(append(append([]byte{}, rest...), quoted...))), layers.LayerTypeIPv6, gopacket.Default)
}

// icmpv6ErrorQuote returns the packet quoted by an ICMPv6 error: everything after the type-specific word.
func icmpv6ErrorQuote(t *testing.T, packet gopacket.Packet) gopacket.Packet {
	t.Helper()
	icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || len(icmp.Payload) < icmpErrorRestHeaderSize {
		t.Fatalf("missing translated ICMPv6 error: %v", packet.ErrorLayer())
	}
	return gopacket.NewPacket(icmp.Payload[icmpErrorRestHeaderSize:], layers.LayerTypeIPv6, gopacket.Default)
}

func zeroRestHeader() []byte { return make([]byte, icmpErrorRestHeaderSize) }

// ipv4ICMPPacket builds an ICMPv4 message travelling back along the path of the ipv4Source -> ipv4Dest fixtures,
// so an error built with it quotes a packet that really went from its destination to its source.
func ipv4ICMPPacket(t *testing.T, messageType, code uint8, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Dest, DstIP: ipv4Source}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(messageType, code)}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

func ipv6ICMPPacket(t *testing.T, messageType, code uint8, payload []byte) gopacket.Packet {
	return ipv6ICMPPacketWithRestHeader(t, messageType, code, make([]byte, icmpErrorRestHeaderSize), payload)
}

// ipv6ICMPPacketWithRestHeader builds an ICMPv6 message travelling back along the path of the ipv6Source -> ipv6Dest
// fixtures, so an error built with it quotes a packet that really went from its destination to its source.
func ipv6ICMPPacketWithRestHeader(t *testing.T, messageType, code uint8, restHeader, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Dest, DstIP: ipv6Source}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(messageType, code)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	if len(restHeader) != icmpErrorRestHeaderSize {
		t.Fatalf("ICMPv6 rest header must be %d bytes, got %d", icmpErrorRestHeaderSize, len(restHeader))
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(append(restHeader, payload...))), layers.LayerTypeIPv6, gopacket.Default)
}

func icmpPointer(pointer uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, pointer)
	return result
}

func icmpPointerValue(t *testing.T, payload []byte) uint32 {
	t.Helper()
	if len(payload) < 4 {
		t.Fatalf("ICMP Parameter Problem payload is too short: %d", len(payload))
	}
	return binary.BigEndian.Uint32(payload[:4])
}

func tcpSegment(t *testing.T, network gopacket.NetworkLayer, payload []byte) []byte {
	t.Helper()
	tcp := &layers.TCP{
		SrcPort: testSourcePort, DstPort: testTCPDestinationPort, Seq: testTCPSequence,
		ACK: true, Window: testTCPWindow, DataOffset: 5,
	}
	if err := tcp.SetNetworkLayerForChecksum(network); err != nil {
		t.Fatal(err)
	}
	return serializeTestPacket(t, tcp, gopacket.Payload(payload))
}

func translatorWithMTU(t *testing.T, mtu uint32) *siit.Translator {
	t.Helper()
	_, nat64Net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}
	translator, err := siit.NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, nil, mtu)
	if err != nil {
		t.Fatal(err)
	}
	return translator
}

// ipv4EchoRequest builds an ICMPv4 Echo Request travelling from ipv4Source to ipv4Dest.
func ipv4EchoRequest(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(echoRequest, 0)}
	return gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
}

// Transport kinds understood by ipv4Segment and ipv6Segment.
const (
	segmentTCP  = "TCP"
	segmentUDP  = "UDP"
	segmentICMP = "ICMP"
)

// segmentPayload is the data every ipv4Segment and ipv6Segment carries.
var segmentPayload = []byte("hello")

// ipv4Segment builds a valid IPv4 packet carrying a TCP, UDP or ICMP Echo Request message with the given addresses.
func ipv4Segment(t *testing.T, kind string, source, destination net.IP, ttl uint8) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TOS: testTrafficClass, Id: 0x1234, TTL: ttl, SrcIP: source, DstIP: destination}
	var transport gopacket.SerializableLayer
	switch kind {
	case segmentTCP:
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, Seq: testTCPSequence, ACK: true, Window: testTCPWindow}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = tcp
	case segmentUDP:
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = udp
	case segmentICMP:
		ip.Protocol = layers.IPProtocolICMPv4
		transport = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(echoRequest, 0), Id: 1, Seq: 1}
	default:
		t.Fatalf("unknown segment kind %q", kind)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, transport, gopacket.Payload(segmentPayload)), layers.LayerTypeIPv4, gopacket.Default)
}

// ipv6Segment is the IPv6 counterpart of ipv4Segment.
func ipv6Segment(t *testing.T, kind string, source, destination net.IP, hopLimit uint8) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, TrafficClass: testTrafficClass, HopLimit: hopLimit, SrcIP: source, DstIP: destination}
	var transport []gopacket.SerializableLayer
	switch kind {
	case segmentTCP:
		ip.NextHeader = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, Seq: testTCPSequence, ACK: true, Window: testTCPWindow}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = []gopacket.SerializableLayer{tcp}
	case segmentUDP:
		ip.NextHeader = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = []gopacket.SerializableLayer{udp}
	case segmentICMP:
		ip.NextHeader = layers.IPProtocolICMPv6
		icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
		if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = []gopacket.SerializableLayer{icmp, &layers.ICMPv6Echo{Identifier: 1, SeqNumber: 1}}
	default:
		t.Fatalf("unknown segment kind %q", kind)
	}
	packetLayers := append([]gopacket.SerializableLayer{ip}, transport...)
	return gopacket.NewPacket(serializeTestPacket(t, append(packetLayers, gopacket.Payload(segmentPayload))...), layers.LayerTypeIPv6, gopacket.Default)
}

// withIPv4Byte returns a copy of an IPv4 packet with one header octet replaced and the header checksum fixed.
func withIPv4Byte(t *testing.T, packet gopacket.Packet, offset int, value uint8) gopacket.Packet {
	t.Helper()
	data := append([]byte(nil), packet.Data()...)
	data[offset] = value
	data[ipv4ChecksumOffset], data[ipv4ChecksumOffset+1] = 0, 0
	binary.BigEndian.PutUint16(data[ipv4ChecksumOffset:], checksum(data[:int(data[0]&0x0f)*4]))
	return gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
}

// withTTL returns a copy of an IPv4 packet with another TTL and a matching header checksum.
func withTTL(t *testing.T, packet gopacket.Packet, ttl uint8) gopacket.Packet {
	return withIPv4Byte(t, packet, ipv4TTLOffset, ttl)
}

// withTOS returns a copy of an IPv4 packet with another TOS and a matching header checksum.
func withTOS(t *testing.T, packet gopacket.Packet, tos uint8) gopacket.Packet {
	return withIPv4Byte(t, packet, ipv4TOSOffset, tos)
}

// withHopLimit returns a copy of an IPv6 packet with another Hop Limit (it is not covered by any checksum).
func withHopLimit(t *testing.T, packet gopacket.Packet, hopLimit uint8) gopacket.Packet {
	t.Helper()
	data := append([]byte(nil), packet.Data()...)
	data[ipv6HopLimitOffset] = hopLimit
	return gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default)
}

// ipv6TCPPayloadPacket builds a TCP packet from ipv6Source to ipv6Dest with the given payload.
func ipv6TCPPayloadPacket(t *testing.T, payload []byte) gopacket.Packet {
	return ipv6TCPPayloadPacketWithOptions(t, payload, nil)
}

// ipv6UDPPayloadPacket builds a UDP packet from ipv6Source to ipv6Dest with the given payload.
func ipv6UDPPayloadPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, TrafficClass: testTrafficClass, NextHeader: layers.IPProtocolUDP, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
}

func ipv6TCPPayloadPacketWithOptions(t *testing.T, payload []byte, options []layers.TCPOption) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv6{Version: 6, TrafficClass: testTrafficClass, NextHeader: layers.IPProtocolTCP, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
	tcp := &layers.TCP{SrcPort: testSourcePort, DstPort: testTCPDestinationPort, Seq: testTCPSequence, ACK: true, Window: testTCPWindow, Options: options}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload(payload)), layers.LayerTypeIPv6, gopacket.Default)
}

// icmpv6Result is an ICMPv4 message translated to ICMPv6, split into its layers.
type icmpv6Result struct {
	packet gopacket.Packet
	ip     *layers.IPv6
	icmp   *layers.ICMPv6
	raw    []byte
}

// translateToICMPv6 translates an IPv4 packet that must yield an ICMPv6 message with a valid checksum.
func translateToICMPv6(t *testing.T, translator *siit.Translator, input gopacket.Packet) icmpv6Result {
	t.Helper()
	raw := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	icmp, ok2 := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok || !ok2 || int(ip.Length) != len(raw)-ipv6HeaderLength {
		t.Fatalf("translation is not an ICMPv6 packet with a consistent length: %v", packet.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
		t.Fatalf("translated ICMPv6 checksum is invalid: %#x", icmp.Checksum)
	}
	return icmpv6Result{packet: packet, ip: ip, icmp: icmp, raw: raw}
}

// quote returns the packet quoted by the ICMPv6 error (after the four-byte type-specific word).
func (r icmpv6Result) quote(t *testing.T) gopacket.Packet { return icmpv6ErrorQuote(t, r.packet) }

// icmpv4Result is an ICMPv6 message translated to ICMPv4, split into its layers.
type icmpv4Result struct {
	packet gopacket.Packet
	ip     *layers.IPv4
	icmp   *layers.ICMPv4
	raw    []byte
}

// translateToICMPv4 translates an IPv6 packet that must yield an ICMPv4 message with valid checksums.
func translateToICMPv4(t *testing.T, translator *siit.Translator, input gopacket.Packet) icmpv4Result {
	t.Helper()
	raw := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv6(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmp, ok2 := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || !ok2 || int(ip.Length) != len(raw) || ip.Checksum != ipv4HeaderChecksum(ip) {
		t.Fatalf("translation is not an ICMPv4 packet with a consistent length and header checksum: %v", packet.ErrorLayer())
	}
	if icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
		t.Fatalf("translated ICMPv4 checksum is invalid: %#x", icmp.Checksum)
	}
	return icmpv4Result{packet: packet, ip: ip, icmp: icmp, raw: raw}
}

// quote returns the packet quoted by the ICMPv4 error.
func (r icmpv4Result) quote() gopacket.Packet {
	return gopacket.NewPacket(r.icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
}
