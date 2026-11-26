package siit_test

import (
	"errors"
	"fmt"
	"net/netip"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// A CLAT with the Well-Known Prefix uses a non-global router address, so it maps that address to its own IPv6
// address with an EAM entry, next to the entry for the IPv4 address of the host.
func ExampleNewTranslator() {
	router, err := siit.ParseEAMEntry("192.0.0.254", "2001:db8::254")
	if err != nil {
		panic(err)
	}

	host, err := siit.ParseEAMEntry("192.0.0.1", "2001:db8::1")
	if err != nil {
		panic(err)
	}

	_, err = siit.NewTranslator(siit.Config{
		NAT64Prefix:       netip.MustParsePrefix("64:ff9b::/96"),
		IPv4RouterAddress: netip.MustParseAddr("192.0.0.254"),
		EAMTable:          siit.EAMTable{router, host},
	})
	fmt.Println(err)
	// Output: <nil>
}

func ExampleTranslator_TranslateIPv4() {
	translator := exampleTranslator()

	// A packet as read from a tun device, starting at the IPv4 header.
	packet := exampleIPv4Packet()

	result, err := translator.TranslateIPv4(packet)
	var translationErr *siit.TranslationError
	switch {
	case errors.As(err, &translationErr):
		// Send translationErr.Reply back out the IPv4 side.
	case err != nil:
		// Log the rejected packet.
	case len(result) > 0:
		// Send result out the IPv6 side.
		fmt.Println(result.Version(), result.Src(), "->", result.Dst())
	}
	// Output: 6 2001:db8:64::c000:20a -> 2001:db8:64::c633:6414
}

func ExampleTranslator_TranslateIPv6Layer() {
	translator := exampleTranslator()

	// A packet that the caller already decoded with gopacket.
	packet := gopacket.NewPacket(exampleIPv6Packet(), layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)

	result, err := translator.TranslateIPv6Layer(ip)
	if err != nil {
		panic(err)
	}

	udp := result.Decode().Layer(layers.LayerTypeUDP).(*layers.UDP)
	fmt.Println(result.Version(), result.Src(), "->", result.Dst(), "port", uint16(udp.DstPort))
	// Output: 4 198.51.100.20 -> 192.0.2.10 port 40000
}

func exampleTranslator() *siit.Translator {
	translator, err := siit.NewTranslator(siit.Config{
		NAT64Prefix:       netip.MustParsePrefix("2001:db8:64::/96"),
		IPv4RouterAddress: netip.MustParseAddr("192.0.2.1"),
	})
	if err != nil {
		panic(err)
	}

	return translator
}

func exampleIPv4Packet() []byte {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.10").AsSlice(), DstIP: netip.MustParseAddr("198.51.100.20").AsSlice(),
	}
	return exampleUDPPacket(ip, 40000, 53)
}

func exampleIPv6Packet() []byte {
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
		SrcIP: netip.MustParseAddr("2001:db8:64::c633:6414").AsSlice(), DstIP: netip.MustParseAddr("2001:db8:64::c000:20a").AsSlice(),
	}
	return exampleUDPPacket(ip, 53, 40000)
}

func exampleUDPPacket(ip gopacket.NetworkLayer, sourcePort, destinationPort layers.UDPPort) []byte {
	udp := &layers.UDP{SrcPort: sourcePort, DstPort: destinationPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, ip.(gopacket.SerializableLayer), udp, gopacket.Payload("hello")); err != nil {
		panic(err)
	}

	return buffer.Bytes()
}
