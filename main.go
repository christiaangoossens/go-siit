package siit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Translator converts packets between IPv4 and IPv6 according to SIIT.
type Translator struct {
	nat64Net          *net.IPNet
	ipv4RouterAddress net.IP
}

type TranslationOverrides struct {
	SourceIP            net.IP
	DestinationIP       net.IP
	PreventTTLDecrement bool
}

var (
	ErrInvalidPacket       = errors.New("Invalid packet")
	ErrInvalidICMP         = errors.New("Invalid ICMP packet")
	ErrUnsupportedProtocol = errors.New("Unsupported protocol")
	ErrTimeExceeded        = errors.New("TTL or Hop Limit expired")
	ErrUnsupportedSrcIP    = errors.New("Unsupported source IP address")
	ErrUnsupportedDestIP   = errors.New("Unsupported destination IP address")
	ErrPacketOversized     = errors.New("Packet is too large to be translated without possible fragmentation")
)

type TranslationError struct {
	// Error that occurred during translation.
	Err error
	// Packet generated as a result of this error for sending back to the source of the original packet.
	Packet []byte
}

func (e *TranslationError) Error() string {
	return e.Err.Error()
}

func (e *TranslationError) Unwrap() error {
	return e.Err
}

// NewTranslator creates a SIIT translator with the addresses used for routing
// and ICMP error generation.
func NewTranslator(nat64Net *net.IPNet, ipv4RouterAddress net.IP) (*Translator, error) {
	// Check that NAT64 net is a /96 prefix
	if nat64Net == nil || nat64Net.Mask == nil {
		return nil, fmt.Errorf("Invalid NAT64 prefix: %v", nat64Net)
	}

	maskSize, _ := nat64Net.Mask.Size()
	if maskSize != 96 {
		return nil, fmt.Errorf("NAT64 prefix must be a /96 prefix, got: %v", nat64Net)
	}

	// Check that the IPv4 router address is a valid IPv4 address
	if ipv4RouterAddress == nil || ipv4RouterAddress.To4() == nil {
		return nil, fmt.Errorf("Invalid IPv4 router address: %v", ipv4RouterAddress)
	}

	return &Translator{
		nat64Net:          nat64Net,
		ipv4RouterAddress: ipv4RouterAddress,
	}, nil
}

func (t *Translator) serializePacket(layers ...gopacket.SerializableLayer) []byte {
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, layers...)

	if err != nil {
		log.Printf("Failed to serialize packet: %v", err)
		return nil
	}

	return buffer.Bytes()
}

// RFC 6052 mapping function
func (t *Translator) mapIPv4ToIPv6(ipv4 net.IP) net.IP {
	// Create a new IPv6 address with the NAT64 prefix
	ipv6 := make(net.IP, net.IPv6len)
	copy(ipv6, t.nat64Net.IP)

	// Embed the IPv4 address into the IPv6 address according to RFC 6052
	copy(ipv6[12:], ipv4.To4())

	return ipv6
}

// TranslateIPv4 translates an IPv4 packet to IPv6.
func (t *Translator) TranslateIPv4(packet gopacket.Packet, overrides TranslationOverrides) ([]byte, error) {
	// Translate an IPv4 packet to an IPv6 packet
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// Not IPv4 packet, ignore because we are only translating IPv4 here
		return nil, fmt.Errorf("%w: packet has no IPv4 layer", ErrInvalidPacket)
	}

	ip, _ := ipLayer.(*layers.IPv4)

	// PreventTTLDecrement is already used by ICMP quote translation to mark
	// an embedded packet. Embedded packets have already passed ingress checks.
	quotedPacket := overrides.PreventTTLDecrement

	// RFC 791 Section 3.1 defines a 20-byte minimum IPv4 header and requires
	// Total Length to include that header; reject packets that cannot be parsed.
	if ip == nil || ip.Version != 4 || ip.IHL < 5 || len(ip.Contents) < int(ip.IHL)*4 || ip.Length < uint16(ip.IHL)*4 {
		return nil, fmt.Errorf("%w: invalid IPv4 header", ErrInvalidPacket)
	}
	for _, option := range ip.Options {
		// RFC 7915 Section 4.1 says an unexpired IPv4 source route MUST cause
		// the packet to be discarded because IPv4 options are not translated.
		if option.OptionType == 131 || option.OptionType == 137 {
			return nil, nil
		}
	}

	if !quotedPacket && !validIPv4HeaderChecksum(ip) {
		return nil, fmt.Errorf("%w: invalid IPv4 header checksum", ErrInvalidPacket)
	}

	// Check packet size
	if ip.Length > 1260 {
		return nil, fmt.Errorf("%w: IPv4 packet length %d exceeds 1260 bytes", ErrPacketOversized, ip.Length)
	}

	// Check if TTL would be 0, if so generate an ICMP Time Exceeded message back to the source of the original packet
	if ip.TTL <= 1 {
		packet := t.generateIPv6TimeExceeded(ip)
		return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet}
	}

	protocol := ip.Protocol
	if protocol == layers.IPProtocolIGMP {
		return nil, nil
	}

	if protocol == layers.IPProtocolICMPv4 {
		if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
			return nil, fmt.Errorf("%w: fragmented ICMPv4 packets are unsupported", ErrUnsupportedProtocol)
		}
		protocol = layers.IPProtocolICMPv6
	}

	fragmented := ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0
	// RFC 7915 Section 1.2 states that fragmented ICMP/ICMPv6 packets are not
	// translated; RFC 792 defines an 8-byte minimum ICMPv4 header.
	if !fragmented && ip.Protocol == layers.IPProtocolICMPv4 && len(ip.Payload) < 8 {
		return nil, ErrInvalidICMP
	}

	if !fragmented && !quotedPacket && ip.Protocol != layers.IPProtocolUDP && !validTransportChecksum(ip, ip.Protocol, ip.Payload) {
		return nil, fmt.Errorf("%w: invalid IPv4 transport checksum", ErrInvalidPacket)
	}

	// Verify that src and dst are both unicast
	if !ip.SrcIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv4 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv4 destination %s is not unicast", ErrUnsupportedDestIP, ip.DstIP)
	}

	// If IP overrides are provided, use them; otherwise, map the addresses
	var srcIP, dstIP net.IP
	if overrides.SourceIP != nil {
		srcIP = overrides.SourceIP
	} else {
		srcIP = t.mapIPv4ToIPv6(ip.SrcIP)
	}

	if overrides.DestinationIP != nil {
		dstIP = overrides.DestinationIP
	} else {
		dstIP = t.mapIPv4ToIPv6(ip.DstIP)
	}

	ttl := t.decrementHopLimit(ip.TTL)
	if overrides.PreventTTLDecrement == true {
		ttl = ip.TTL
	}

	// Create a new IPv6 packet that matches the IPv4 Packet without any payload
	ipv6 := &layers.IPv6{
		Version:      6,
		TrafficClass: ip.TOS,
		FlowLabel:    0,
		NextHeader:   protocol,
		HopLimit:     ttl,
		SrcIP:        srcIP,
		DstIP:        dstIP,
	}

	var payload []byte
	var dropped bool

	if fragmented {
		// RFC 7915 Section 4.1 requires an IPv6 Fragment Header for an already
		// fragmented IPv4 packet and copies its offset, M flag, and identifier.
		ipv6.NextHeader = layers.IPProtocolIPv6Fragment
		fragmentHeader := make([]byte, 8)
		fragmentHeader[0] = byte(protocol)
		binary.BigEndian.PutUint16(fragmentHeader[2:4], ip.FragOffset<<3)
		if ip.Flags&layers.IPv4MoreFragments != 0 {
			fragmentHeader[3] |= 1
		}
		binary.BigEndian.PutUint32(fragmentHeader[4:8], uint32(ip.Id))
		result := t.serializePacket(ipv6, gopacket.Payload(append(fragmentHeader, ip.Payload...)))
		if result == nil {
			return nil, fmt.Errorf("%w: failed to serialize IPv6 fragment", ErrInvalidPacket)
		}
		return result, nil
	}

	switch protocol {
	case layers.IPProtocolICMPv6:
		payload, dropped = t.translateICMPv4(ipv6, ip.Payload)
	case layers.IPProtocolTCP:
		payload = t.translateTCPv4(ipv6, ip.Payload)
	case layers.IPProtocolUDP:
		payload = t.translateUDPv4(ipv6, ip.Payload)
	default:
		payload = ip.Payload
		// RFC 7915 Section 4.1 requires unsupported transport protocols to be
		// forwarded unchanged; reject only a payload too short to be a packet.
		if len(payload) < 4 {
			return nil, fmt.Errorf("%w: IPv4 protocol %d payload", ErrUnsupportedProtocol, protocol)
		}
	}
	if dropped {
		return nil, nil
	}

	// A non-dropped nil ICMP payload indicates a malformed or structurally invalid packet.
	if payload == nil {
		if protocol == layers.IPProtocolICMPv6 {
			return nil, ErrInvalidICMP
		}
		return nil, fmt.Errorf("%w: IPv4 protocol %d payload", ErrInvalidPacket, protocol)
	}

	result := t.serializePacket(ipv6, gopacket.Payload(payload))
	if result == nil {
		return nil, fmt.Errorf("%w: failed to serialize IPv6 packet", ErrInvalidPacket)
	}

	return result, nil
}

func (t *Translator) translateTCPv4(ip *layers.IPv6, payload []byte) []byte {
	if len(payload) < 20 {
		return nil
	}

	// Parse TCP packet
	tcpLayer := gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.Default)
	tcp, ok := tcpLayer.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcpLayer.ErrorLayer() != nil {
		return nil
	}

	err := tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for TCPv6 checksum: %v", err)
		return nil
	}

	return t.serializePacket(tcp, gopacket.Payload(tcp.Payload))
}

func (t *Translator) translateUDPv4(ip *layers.IPv6, payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}

	// Parse UDP packet
	udpLayer := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)
	udp, ok := udpLayer.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return nil
	}

	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for UDPv6 checksum: %v", err)
		return nil
	}

	return t.serializePacket(udp, gopacket.Payload(udp.Payload))
}

// TranslateIPv6 translates an IPv6 packet to IPv4.
func (t *Translator) TranslateIPv6(packet gopacket.Packet, overrides TranslationOverrides) ([]byte, error) {
	// Translate an IPv6 packet to an IPv4 packet
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil {
		// Not IPv6 packet, ignore because we are only translating IPv6 here
		return nil, fmt.Errorf("%w: packet has no IPv6 layer", ErrInvalidPacket)
	}

	ip, _ := ipLayer.(*layers.IPv6)

	// PreventTTLDecrement is the existing marker for an embedded ICMP quote;
	// do not reapply ingress checksum checks to that normalized inner packet.
	quotedPacket := overrides.PreventTTLDecrement

	// RFC 8200 Section 3 defines a fixed 40-byte IPv6 base header.
	if ip == nil || ip.Version != 6 || len(ip.Contents) < ipv6HeaderLength {
		return nil, fmt.Errorf("%w: invalid IPv6 header", ErrInvalidPacket)
	}

	// Check if TTL would be 0, if so generate an ICMP Time Exceeded message back to the source of the original packet
	if ip.HopLimit <= 1 {
		packet := t.generateIPv4TimeExceeded(ip)
		return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet}
	}

	// Get the actual contents, skip over any IPv6 extensions (as per RFC 7915)
	protocol := ip.NextHeader
	sanitizedPayload := ip.Payload
	for _, layer := range packet.Layers() {
		switch extension := layer.(type) {
		case *layers.IPv6HopByHop:
			protocol = extension.NextHeader
			sanitizedPayload = extension.Payload
		case *layers.IPv6Routing:
			if extension.SegmentsLeft != 0 {
				result := t.generateIPv6ParameterProblem(ip, 43)
				return result, fmt.Errorf("%w: IPv6 routing header has segments left", ErrInvalidPacket)
			}
			protocol = extension.NextHeader
			sanitizedPayload = extension.Payload
		case *layers.IPv6Destination:
			protocol = extension.NextHeader
			sanitizedPayload = extension.Payload
		}
	}

	if !quotedPacket && (protocol == layers.IPProtocolTCP || (protocol == layers.IPProtocolICMPv6 && shouldValidateICMPv6(ip.Payload))) {
		if !validTransportChecksum(ip, protocol, sanitizedPayload) {
			return nil, fmt.Errorf("%w: invalid IPv6 transport checksum", ErrInvalidPacket)
		}
	}

	// ICMPv6 errors may use the IPv4 router address when the outer IPv6
	// destination cannot be mapped to an IPv4 address. This is allowed by RFC 7915
	// Section 4.1, which states that the IPv4 router address may be used when the
	// outer IPv6 destination is not mappable to an IPv4 address.
	canUseDifferentDstIP := false
	if protocol == layers.IPProtocolICMPv6 {
		decodedICMP := gopacket.NewPacket(sanitizedPayload, layers.LayerTypeICMPv6, gopacket.Default)
		icmp, ok := decodedICMP.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		// RFC 4443 defines types 0-127 as errors and 128-255 as informational messages.
		canUseDifferentDstIP = ok && icmp.TypeCode.Type() < 128
		protocol = layers.IPProtocolICMPv4
	}

	// Verify that src and dst are both unicast
	if !ip.SrcIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv6 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: IPv6 destination %s is not unicast", ErrUnsupportedDestIP, ip.DstIP)
	}

	// Determine source IP
	var srcIP net.IP
	if overrides.SourceIP != nil {
		srcIP = overrides.SourceIP
	} else if t.nat64Net.Contains(ip.SrcIP) {
		srcIP = ip.SrcIP[12:]
	} else {
		srcIP = t.ipv4RouterAddress
	}

	// Determine destination IP
	var dstIP net.IP
	if overrides.DestinationIP != nil {
		dstIP = overrides.DestinationIP
	} else {
		if !t.nat64Net.Contains(ip.DstIP) {
			if !canUseDifferentDstIP {
				return nil, fmt.Errorf("%w: IPv6 destination %s is not mappable", ErrInvalidPacket, ip.DstIP)
			}
			dstIP = t.ipv4RouterAddress
		} else {
			dstIP = ip.DstIP[12:]
		}
	}

	ttl := t.decrementHopLimit(ip.HopLimit)
	if overrides.PreventTTLDecrement == true {
		ttl = ip.HopLimit
	}

	// Create a new IPv4 packet that matches the IPv6 Packet without any payload
	ipv4 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        ip.TrafficClass,
		Length:     0, // Automatically calculated during serialization
		Id:         0, // Overwritten for fragments
		Flags:      0, // Overwritten for fragments
		FragOffset: 0, // Overwritten for fragments
		TTL:        ttl,
		Protocol:   protocol,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	var payload []byte
	var dropped bool

	switch protocol {
	case layers.IPProtocolICMPv4:
		payload, dropped = t.translateICMPv6(dstIP, ip.Payload)
	case layers.IPProtocolTCP:
		payload = t.translateTCPv6(ipv4, sanitizedPayload)
	case layers.IPProtocolUDP:
		payload = t.translateUDPv6(ipv4, sanitizedPayload)
	case layers.IPProtocolIPv6Fragment:
		fragmentLayer := packet.Layer(layers.LayerTypeIPv6Fragment)
		if fragmentLayer == nil {
			// Invalid packet, drop
			log.Printf("Dropping invalid fragmented IPv6 packet without any actual fragment in it")
			return nil, fmt.Errorf("%w: IPv6 fragments are unsupported", ErrUnsupportedProtocol)
		}

		fragment, _ := fragmentLayer.(*layers.IPv6Fragment)
		// RFC 8200 Section 4.5 requires an M=1 fragment's payload to be an
		// integer multiple of 8 octets. Reserved fields are ignored on reception.
		if fragment == nil {
			return nil, fmt.Errorf("%w: missing IPv6 fragment header", ErrInvalidPacket)
		}

		if len(fragment.Contents) < 8 || (fragment.MoreFragments && len(fragment.Payload)%8 != 0) {
			return nil, fmt.Errorf("%w: invalid IPv6 fragment", ErrInvalidPacket)
		}
		if fragment.NextHeader == layers.IPProtocolICMPv6 {
			return nil, fmt.Errorf("%w: fragmented ICMPv6 packets are unsupported", ErrUnsupportedProtocol)
		}

		ipv4.FragOffset = fragment.FragmentOffset
		ipv4.Id = uint16(fragment.Identification)

		if fragment.MoreFragments {
			ipv4.Flags = 1 << 0 // MF flag
		}

		ipv4.Protocol = fragment.NextHeader
		payload = fragment.Payload
		// RFC 7915 Section 5.1.1 says a Fragment Header followed by an
		// extension header should be dropped because IPv4 cannot represent it.
		if fragment.NextHeader == layers.IPProtocolIPv6HopByHop || fragment.NextHeader == layers.IPProtocolIPv6Routing || fragment.NextHeader == layers.IPProtocolIPv6Destination || fragment.NextHeader == layers.IPProtocolIPv6Fragment {
			return nil, nil
		}
	default:
		// Unknown protocols are forwarded as opaque payloads.
		payload = sanitizedPayload
	}
	if dropped {
		return nil, nil
	}

	if payload == nil {
		if protocol == layers.IPProtocolICMPv4 {
			return nil, ErrInvalidICMP
		}
		return nil, fmt.Errorf("%w: IPv6 protocol %d payload", ErrInvalidPacket, protocol)
	}

	result := t.serializePacket(ipv4, gopacket.Payload(payload))
	if result == nil {
		return nil, fmt.Errorf("%w: failed to serialize IPv4 packet", ErrInvalidPacket)
	}

	return result, nil
}

func (t *Translator) decrementHopLimit(value uint8) uint8 {
	if value == 0 {
		return 0
	}

	return value - 1
}

func (t *Translator) translateTCPv6(ip *layers.IPv4, payload []byte) []byte {
	if len(payload) < 20 {
		return nil
	}

	// Parse TCP packet
	tcpLayer := gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.Default)
	tcp, ok := tcpLayer.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcpLayer.ErrorLayer() != nil {
		return nil
	}

	err := tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for TCPv4 checksum: %v", err)
		return nil
	}

	return t.serializePacket(tcp, gopacket.Payload(tcp.Payload))
}

func (t *Translator) translateUDPv6(ip *layers.IPv4, payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}

	// Parse UDP packet
	udpLayer := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)
	udp, ok := udpLayer.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || udp.Checksum == 0 {
		return nil
	}

	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for UDPv4 checksum: %v", err)
		return nil
	}

	return t.serializePacket(udp, gopacket.Payload(udp.Payload))
}
