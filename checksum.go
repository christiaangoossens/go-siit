package siit

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket/layers"
)

/**
 * Internet checksum (RFC 1071, RFC 1624)
 */

// Minimum length and checksum offset of every transport protocol with a checksum.
var checksummedProtocols = map[layers.IPProtocol]struct{ headerLength, checksumOffset int }{
	layers.IPProtocolTCP:    {20, 16},
	layers.IPProtocolUDP:    {8, 6},
	layers.IPProtocolICMPv4: {8, 2},
	layers.IPProtocolICMPv6: {8, 2},
}

// Only the last part may have an odd length.
func internetChecksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for index := 0; index+1 < len(part); index += 2 {
			sum += uint32(binary.BigEndian.Uint16(part[index:]))
		}
		if len(part)%2 == 1 {
			sum += uint32(part[len(part)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}

	return ^uint16(sum)
}

// RFC 1624 Equation 3: both slices must have an even length.
func adjustChecksum(checksum uint16, removed, added []byte) uint16 {
	sum := uint32(^checksum)
	for index := 0; index+1 < len(removed); index += 2 {
		sum += uint32(^binary.BigEndian.Uint16(removed[index:]))
	}
	for index := 0; index+1 < len(added); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(added[index:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}

	return ^uint16(sum)
}

// The ICMPv4 checksum has no pseudo-header (RFC 792).
func ipv4PseudoHeader(source, destination net.IP, protocol layers.IPProtocol, length int) []byte {
	if protocol == layers.IPProtocolICMPv4 {
		return nil
	}

	header := make([]byte, 12)
	copy(header[0:4], source.To4())
	copy(header[4:8], destination.To4())
	header[9] = byte(protocol)
	binary.BigEndian.PutUint16(header[10:12], uint16(length))
	return header
}

// RFC 8200 Section 8.1
func ipv6PseudoHeader(source, destination net.IP, protocol layers.IPProtocol, length int) []byte {
	header := make([]byte, 40)
	copy(header[0:16], source.To16())
	copy(header[16:32], destination.To16())
	binary.BigEndian.PutUint32(header[32:36], uint32(length))
	header[39] = byte(protocol)
	return header
}

func validIPv4HeaderChecksum(ip *layers.IPv4) bool {
	return internetChecksum(ip.Contents) == 0
}

// Protocols without a checksum are always valid. A UDP checksum of zero is handled by the caller.
func validTransportChecksum(pseudoHeader []byte, protocol layers.IPProtocol, payload []byte) bool {
	transport, ok := checksummedProtocols[protocol]
	if !ok {
		return true
	}

	return len(payload) >= transport.headerLength && internetChecksum(pseudoHeader, payload) == 0
}

func isZeroUDPChecksum(payload []byte, protocol layers.IPProtocol) bool {
	offset := checksummedProtocols[layers.IPProtocolUDP].checksumOffset
	return protocol == layers.IPProtocolUDP && len(payload) >= offset+2 && binary.BigEndian.Uint16(payload[offset:]) == 0
}
