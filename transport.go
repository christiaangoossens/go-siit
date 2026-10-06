package siit

import (
	"encoding/binary"
	"slices"

	"github.com/google/gopacket/layers"
)

/**
 * RFC 7915 Sections 4.5 and 5.5 (Transport-Layer Header Translation)
 */

// ICMPv4 and ICMPv6 Echo Request/Reply types.
var echoTypes = map[byte]byte{8: 128, 0: 129, 128: 8, 129: 0}

// translateTransport updates the checksum for the changed pseudo-header (RFC 1624), so it also works for the first
// fragment of a segment or a truncated quote. Of ICMP, only a quoted Echo is translated here (RFC 7915 Sections 4.3
// and 5.3). The second return value is true if the packet has to be silently dropped.
func translateTransport(protocol layers.IPProtocol, payload, removed, added []byte, quoted bool) ([]byte, bool) {
	result := slices.Clone(payload)

	switch protocol {
	case layers.IPProtocolTCP, layers.IPProtocolUDP:
		offset := checksummedProtocols[protocol].checksumOffset
		if len(result) < offset+2 {
			// A truncated quote can end before the checksum.
			return result, false
		}

		checksum := binary.BigEndian.Uint16(result[offset:])
		if protocol == layers.IPProtocolUDP && checksum == 0 {
			// Without the whole datagram no checksum can be computed, so only a quote may keep its zero checksum.
			return payload, !quoted
		}

		checksum = adjustChecksum(checksum, removed, added)
		if protocol == layers.IPProtocolUDP && checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(result[offset:], checksum)
	case layers.IPProtocolICMPv4, layers.IPProtocolICMPv6:
		newType, ok := echoTypes[result[0]]
		if !ok || len(result) < 4 {
			// An ICMP error quoting an ICMP error is dropped.
			return nil, true
		}

		// The first 16-bit word is the type and the code, the checksum starts at the third octet.
		removed = append([]byte{result[0], result[1]}, removed...)
		added = append([]byte{newType, result[1]}, added...)
		result[0] = newType
		binary.BigEndian.PutUint16(result[2:], adjustChecksum(binary.BigEndian.Uint16(result[2:]), removed, added))
	default:
		// RFC 7915 Section 4.1 requires unsupported transport protocols to be forwarded unchanged.
		return payload, false
	}

	return result, false
}
