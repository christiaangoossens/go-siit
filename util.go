package siit

import (
	"log"
	"net"

	"github.com/google/gopacket"
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

func serializeTranslatedPacket(options gopacket.SerializeOptions, srcIP, dstIP net.IP, packetLayers ...gopacket.SerializableLayer) TranslatedPacket {
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, options, packetLayers...); err != nil {
		log.Printf("Failed to serialize packet: %v", err)
		return TranslatedPacket{SrcIP: srcIP, DstIP: dstIP}
	}

	return TranslatedPacket{Packet: buffer.Bytes(), SrcIP: srcIP, DstIP: dstIP}
}

func getBit(address net.IP, bitIndex int) byte {
	return address[bitIndex/8] >> uint(7-bitIndex%8) & 1
}

func setBit(address net.IP, bitIndex int, value byte) {
	mask := byte(1 << uint(7-bitIndex%8))
	if value != 0 {
		address[bitIndex/8] |= mask
	} else {
		address[bitIndex/8] &^= mask
	}
}
