package siit

import (
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ipv4HeaderLength            = 20
	ipv6HeaderLength            = 40
	ipv6FragmentHeaderLength    = 8
	ipv4MinimumMTU              = 576
	ipv6MinimumMTU              = 1280
	ipv4MaximumUnfragmentedSize = ipv6MinimumMTU - ipv6HeaderLength + ipv4HeaderLength
)

var (
	// Whole packets get their lengths and checksums computed.
	completeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	// Fragments and quoted packets can be truncated, so they keep the lengths of the original packet.
	partialOptions = gopacket.SerializeOptions{ComputeChecksums: true}
)

// serializePacket writes the IP header in front of the payload. Callers treat an empty packet as a failure.
func serializePacket(options gopacket.SerializeOptions, header gopacket.SerializableLayer, payload []byte) Packet {
	headerLength := ipv4HeaderLength
	if header.LayerType() == layers.LayerTypeIPv6 {
		headerLength = ipv6HeaderLength
	}

	buffer := gopacket.NewSerializeBufferExpectedSize(headerLength, len(payload))
	if err := gopacket.SerializeLayers(buffer, options, header, gopacket.Payload(payload)); err != nil {
		return nil
	}

	return buffer.Bytes()
}

// ipv4Addr converts an address of a decoded IPv4 layer. It is invalid when it is not an IPv4 address.
func ipv4Addr(ip net.IP) netip.Addr {
	address, _ := netip.AddrFromSlice(ip)
	if address = address.Unmap(); !address.Is4() {
		return netip.Addr{}
	}

	return address
}

// ipv6Addr converts an address of a decoded IPv6 layer. It is invalid when it is not an IPv6 address.
func ipv6Addr(ip net.IP) netip.Addr {
	if len(ip) != net.IPv6len {
		return netip.Addr{}
	}

	return netip.AddrFrom16([16]byte(ip))
}

// layerAddresses returns two addresses of the same family as slices for a gopacket layer, with one allocation.
func layerAddresses(source, destination netip.Addr) (net.IP, net.IP) {
	if source.Is4() {
		sourceBytes, destinationBytes := source.As4(), destination.As4()
		addresses := make(net.IP, 2*net.IPv4len)
		copy(addresses, sourceBytes[:])
		copy(addresses[net.IPv4len:], destinationBytes[:])
		return addresses[:net.IPv4len:net.IPv4len], addresses[net.IPv4len:]
	}

	sourceBytes, destinationBytes := source.As16(), destination.As16()
	addresses := make(net.IP, 2*net.IPv6len)
	copy(addresses, sourceBytes[:])
	copy(addresses[net.IPv6len:], destinationBytes[:])
	return addresses[:net.IPv6len:net.IPv6len], addresses[net.IPv6len:]
}

func getBit(address []byte, bitIndex int) byte {
	return address[bitIndex/8] >> uint(7-bitIndex%8) & 1
}

func setBit(address []byte, bitIndex int, value byte) {
	mask := byte(1 << uint(7-bitIndex%8))
	if value != 0 {
		address[bitIndex/8] |= mask
	} else {
		address[bitIndex/8] &^= mask
	}
}
