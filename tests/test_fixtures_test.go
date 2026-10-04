package siit_test

import (
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
	ipv6Source           = net.ParseIP("2001:db8::1")
	ipv6Dest             = net.ParseIP("64:ff9b::101:101")
	ipv6TranslatedSource = ipv4RouterAddress
	ipv6TranslatedDest   = net.ParseIP("1.1.1.1")
	ipv4RouterAddress    = net.ParseIP("192.0.0.2")
)

const (
	ipv4HeaderLength        = 20
	ipv6HeaderLength        = 40
	udpHeaderLength         = 8
	icmpErrorRestHeaderSize = 4
	ipv4ChecksumOffset      = 10
	transportChecksumOffset = 16
	icmpChecksumOffset      = 2
	maxIPv4PacketLength     = 1260
	maxIPv6PacketLength     = 1280
	maxFragmentedIPv4Length = 1252
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
	icmpv4DestUnreachable   = 3
	icmpv6DestUnreachable   = 1
)

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
	header[10], header[11] = 0, 0
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(header[index])<<8 | uint32(header[index+1])
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
	ip := &layers.IPv6{
		Version: 6, TrafficClass: testTrafficClass, NextHeader: layers.IPProtocolTCP,
		HopLimit: hopLimit, SrcIP: ipv6Source, DstIP: ipv6Dest,
	}
	tcp := &layers.TCP{
		SrcPort: testSourcePort, DstPort: testTCPDestinationPort,
		Seq: testTCPSequence, Ack: testTCPAcknowledgement, SYN: true,
		Window: testTCPWindow, DataOffset: 5,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(serializeTestPacket(t, ip, tcp, gopacket.Payload([]byte("hello"))), layers.LayerTypeIPv6, gopacket.Default)
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
