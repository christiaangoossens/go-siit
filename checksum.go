package siit

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/google/gopacket/layers"
)

// Internet checksum (RFC 1071, RFC 1624)

type transportChecksum struct{ headerLength, checksumOffset int }

// Minimum length and checksum offset of every transport protocol with a checksum.
func checksummedProtocol(protocol layers.IPProtocol) (transportChecksum, bool) {
	switch protocol {
	case layers.IPProtocolTCP:
		return transportChecksum{20, 16}, true
	case layers.IPProtocolUDP:
		return transportChecksum{8, 6}, true
	case layers.IPProtocolICMPv4, layers.IPProtocolICMPv6:
		return transportChecksum{8, 2}, true
	}

	return transportChecksum{}, false
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

// Kept small enough to inline, so the header is allocated on the caller's stack.

// The ICMPv4 checksum has no pseudo-header (RFC 792).
func ipv4PseudoHeader(source, destination net.IP, protocol layers.IPProtocol, length int) []byte {
	if protocol == layers.IPProtocolICMPv4 {
		return nil
	}

	header := make([]byte, 12)
	fillIPv4PseudoHeader(header, source, destination, protocol, length)
	return header
}

func fillIPv4PseudoHeader(header []byte, source, destination net.IP, protocol layers.IPProtocol, length int) {
	copy(header[0:4], source.To4())
	copy(header[4:8], destination.To4())
	header[9] = byte(protocol)
	binary.BigEndian.PutUint16(header[10:12], uint16(length))
}

// RFC 8200 Section 8.1
func ipv6PseudoHeader(source, destination net.IP, protocol layers.IPProtocol, length int) []byte {
	header := make([]byte, 40)
	fillIPv6PseudoHeader(header, source, destination, protocol, length)
	return header
}

func fillIPv6PseudoHeader(header []byte, source, destination net.IP, protocol layers.IPProtocol, length int) {
	copy(header[0:16], source.To16())
	copy(header[16:32], destination.To16())
	binary.BigEndian.PutUint32(header[32:36], uint32(length))
	header[39] = byte(protocol)
}

func validIPv4HeaderChecksum(ip *layers.IPv4) bool {
	return internetChecksum(ip.Contents) == 0
}

// Protocols without a checksum are always valid. A UDP checksum of zero is handled by the caller.
func validTransportChecksum(pseudoHeader []byte, protocol layers.IPProtocol, payload []byte) bool {
	transport, ok := checksummedProtocol(protocol)
	if !ok {
		return true
	}

	return len(payload) >= transport.headerLength && internetChecksum(pseudoHeader, payload) == 0
}

func isZeroUDPChecksum(payload []byte, protocol layers.IPProtocol) bool {
	udp, _ := checksummedProtocol(layers.IPProtocolUDP)
	offset := udp.checksumOffset
	return protocol == layers.IPProtocolUDP && len(payload) >= offset+2 && binary.BigEndian.Uint16(payload[offset:]) == 0
}

// zeroUDPChecksumError names the addresses and ports of a UDP payload that isZeroUDPChecksum accepted, so the caller
// can log it.
func zeroUDPChecksumError(source, destination net.IP, payload []byte) error {
	sourcePort := strconv.Itoa(int(binary.BigEndian.Uint16(payload[0:2])))
	destinationPort := strconv.Itoa(int(binary.BigEndian.Uint16(payload[2:4])))
	return fmt.Errorf("%w: %s -> %s", ErrZeroUDPChecksum, net.JoinHostPort(source.String(), sourcePort), net.JoinHostPort(destination.String(), destinationPort))
}
