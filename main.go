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
	// Network prefix used for NAT64 translation, as defined in RFC 6052.
	nat64Net *net.IPNet
	// IPv4 address used for routing and ICMP error generation
	ipv4RouterAddress net.IP
	// EAM table (RFC 7757)
	eamLookup *eamLookup
	// MTU is the IPv6 path MTU used to determine the maximum IPv4 packet size.
	MTU uint32
}

type TranslationOverrides struct {
	QuotedPacket bool
}

type TranslatedPacket struct {
	Packet []byte
	SrcIP  net.IP
	DstIP  net.IP
}

var (
	ErrInvalidPacket       = errors.New("Invalid packet")
	ErrInvalidICMP         = errors.New("Invalid ICMP packet")
	ErrUnsupportedProtocol = errors.New("Unsupported protocol")
	ErrTimeExceeded        = errors.New("TTL or Hop Limit expired")
	ErrUnsupportedSrcIP    = errors.New("Unsupported source IP address")
	ErrUnsupportedDestIP   = errors.New("Unsupported destination IP address")
	ErrPacketOversized     = errors.New("Packet is too large to be translated without possible fragmentation")
	ErrInvalidMTU          = errors.New("MTU is below the IPv6 minimum")
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

// NewTranslator creates a SIIT translator with the default IPv6 minimum MTU.
func NewTranslator(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable) (*Translator, error) {
	return NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, eamTable, ipv6MinimumMTU)
}

// NewTranslatorWithMTU creates a SIIT translator with the supplied IPv6 path MTU.
func NewTranslatorWithMTU(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable, mtu uint32) (*Translator, error) {
	if mtu < ipv6MinimumMTU {
		return nil, ErrInvalidMTU
	}

	if err := validateRFC6052Prefix(nat64Net); err != nil {
		return nil, err
	}

	// Check that the IPv4 router address is a valid IPv4 address
	if ipv4RouterAddress == nil || ipv4RouterAddress.To4() == nil {
		return nil, fmt.Errorf("Invalid IPv4 router address: %v", ipv4RouterAddress)
	}

	eamLookup, err := newEAMLookup(eamTable)
	if err != nil {
		return nil, err
	}

	return &Translator{
		nat64Net:          nat64Net,
		ipv4RouterAddress: ipv4RouterAddress,
		eamLookup:         eamLookup,
		MTU:               mtu,
	}, nil
}

func (t *Translator) maxIPv4PacketLength(fragmented bool) uint32 {
	if fragmented {
		return t.MTU - ipv6HeaderLength - ipv6FragmentHeaderLength + ipv4HeaderLength
	}

	return t.MTU - ipv6HeaderLength + ipv4HeaderLength
}

func (t *Translator) serializePacket(packetLayers ...gopacket.SerializableLayer) []byte {
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, packetLayers...)

	if err != nil {
		log.Printf("Failed to serialize packet: %v", err)
		return nil
	}

	return buffer.Bytes()
}

func (t *Translator) serializeTranslatedPacket(srcIP, dstIP net.IP, packetLayers ...gopacket.SerializableLayer) TranslatedPacket {
	return TranslatedPacket{
		Packet: t.serializePacket(packetLayers...),
		SrcIP:  srcIP,
		DstIP:  dstIP,
	}
}

// TranslateIPv4 translates an IPv4 packet to IPv6.
func (t *Translator) TranslateIPv4(packet gopacket.Packet, overrides TranslationOverrides) (TranslatedPacket, error) {
	translated := TranslatedPacket{}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// Not IPv4 packet, ignore because we are only translating IPv4 here
		return translated, fmt.Errorf("%w: packet has no IPv4 layer", ErrInvalidPacket)
	}

	ip, _ := ipLayer.(*layers.IPv4)
	if ip != nil {
		if ip.SrcIP.To4() != nil {
			translated.SrcIP = t.mapIPv4ToIPv6(ip.SrcIP)
		}
		if ip.DstIP.To4() != nil {
			translated.DstIP = t.mapIPv4ToIPv6(ip.DstIP)
		}
	}

	// RFC 791 Section 3.1 defines a 20-byte minimum IPv4 header and requires
	// Total Length to include that header; reject packets that cannot be parsed.
	if ip == nil || ip.Version != 4 || ip.IHL < 5 || len(ip.Contents) < int(ip.IHL)*4 || ip.Length < uint16(ip.IHL)*4 {
		return translated, fmt.Errorf("%w: invalid IPv4 header", ErrInvalidPacket)
	}

	for _, option := range ip.Options {
		// RFC 7915 Section 4.1 says an unexpired IPv4 source route MUST cause
		// the packet to be discarded because IPv4 options are not translated.
		if option.OptionType == 131 || option.OptionType == 137 {
			return translated, nil
		}

		// Other options are ignored (section 1.2).
	}

	if !overrides.QuotedPacket && !validIPv4HeaderChecksum(ip) {
		return translated, fmt.Errorf("%w: invalid IPv4 header checksum", ErrInvalidPacket)
	}

	fragmented := ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0
	maxIPv4PacketLength := t.maxIPv4PacketLength(fragmented)

	if uint32(ip.Length) > maxIPv4PacketLength {
		return translated, fmt.Errorf("%w: IPv4 packet length %d exceeds %d bytes", ErrPacketOversized, ip.Length, maxIPv4PacketLength)
	}

	// Check if TTL would be 0, if so generate an ICMP Time Exceeded message back to the source of the original packet
	if ip.TTL <= 1 {
		packet := t.generateIPv6TimeExceeded(ip)
		return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet.Packet}
	}

	protocol := ip.Protocol
	if protocol == layers.IPProtocolIGMP {
		return translated, nil
	}

	if protocol == layers.IPProtocolICMPv4 {
		if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
			return translated, fmt.Errorf("%w: fragmented ICMPv4 packets are unsupported", ErrUnsupportedProtocol)
		}
		protocol = layers.IPProtocolICMPv6
	}

	// RFC 7915 Section 1.2 states that fragmented ICMP/ICMPv6 packets are not
	// translated; RFC 792 defines an 8-byte minimum ICMPv4 header.
	if !fragmented && ip.Protocol == layers.IPProtocolICMPv4 && len(ip.Payload) < 8 {
		return translated, ErrInvalidICMP
	}

	if !fragmented && !overrides.QuotedPacket && ip.Protocol != layers.IPProtocolUDP && !validTransportChecksum(ip, ip.Protocol, ip.Payload) {
		return translated, fmt.Errorf("%w: invalid IPv4 transport checksum", ErrInvalidPacket)
	}

	// Verify that src and dst are both unicast
	if !ip.SrcIP.IsGlobalUnicast() {
		return translated, fmt.Errorf("%w: IPv4 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return translated, fmt.Errorf("%w: IPv4 destination %s is not unicast", ErrUnsupportedDestIP, ip.DstIP)
	}

	ttl := t.decrementHopLimit(ip.TTL)
	if overrides.QuotedPacket == true {
		// For quoted packets, we do not decrement the TTL/Hop Limit, as it is already decremented in the outer packet.
		ttl = ip.TTL
	}

	// Create a new IPv6 packet that matches the IPv4 Packet without any payload
	ipv6 := &layers.IPv6{
		Version:      6,
		TrafficClass: ip.TOS,
		FlowLabel:    0,
		NextHeader:   protocol,
		HopLimit:     ttl,
		SrcIP:        translated.SrcIP,
		DstIP:        translated.DstIP,
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
		result := t.serializeTranslatedPacket(ipv6.SrcIP, ipv6.DstIP, ipv6, gopacket.Payload(append(fragmentHeader, ip.Payload...)))
		if result.Packet == nil {
			return result, fmt.Errorf("%w: failed to serialize IPv6 fragment", ErrInvalidPacket)
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
			return translated, fmt.Errorf("%w: IPv4 protocol %d payload", ErrUnsupportedProtocol, protocol)
		}
	}
	if dropped {
		return translated, nil
	}

	// A non-dropped nil ICMP payload indicates a malformed or structurally invalid packet.
	if payload == nil {
		if protocol == layers.IPProtocolICMPv6 {
			return translated, ErrInvalidICMP
		}
		return translated, fmt.Errorf("%w: IPv4 protocol %d payload", ErrInvalidPacket, protocol)
	}

	result := t.serializeTranslatedPacket(ipv6.SrcIP, ipv6.DstIP, ipv6, gopacket.Payload(payload))
	if result.Packet == nil {
		return result, fmt.Errorf("%w: failed to serialize IPv6 packet", ErrInvalidPacket)
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
func (t *Translator) TranslateIPv6(packet gopacket.Packet, overrides TranslationOverrides) (TranslatedPacket, error) {
	translated := TranslatedPacket{}

	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil {
		// Not IPv6 packet, ignore because we are only translating IPv6 here
		return translated, fmt.Errorf("%w: packet has no IPv6 layer", ErrInvalidPacket)
	}

	ip, _ := ipLayer.(*layers.IPv6)
	if ip != nil {
		if ip.SrcIP.To16() != nil {
			translated.SrcIP = t.mapIPv6ToIPv4(ip.SrcIP)
		}
		if ip.DstIP.To16() != nil {
			translated.DstIP = t.mapIPv6ToIPv4(ip.DstIP)
		}
	}

	// RFC 8200 Section 3 defines a fixed 40-byte IPv6 base header.
	if ip == nil || ip.Version != 6 || len(ip.Contents) < ipv6HeaderLength {
		return translated, fmt.Errorf("%w: invalid IPv6 header", ErrInvalidPacket)
	}

	// Check if TTL would be 0, if so generate an ICMP Time Exceeded message back to the source of the original packet
	if ip.HopLimit <= 1 {
		packet := t.generateIPv4TimeExceeded(ip)
		return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet.Packet}
	}

	// Get the actual contents, skip over any IPv6 extensions (as per RFC 7915, section 1.2)
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

	// Only enforce transport checksums for TCP and ICMPv6 packets, as UDP checksums are optional.
	if !overrides.QuotedPacket && (protocol == layers.IPProtocolTCP || (protocol == layers.IPProtocolICMPv6 && shouldValidateICMPv6(sanitizedPayload))) {
		if !validTransportChecksum(ip, protocol, sanitizedPayload) {
			return translated, fmt.Errorf("%w: invalid IPv6 transport checksum", ErrInvalidPacket)
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
		return translated, fmt.Errorf("%w: IPv6 source %s is not unicast", ErrUnsupportedSrcIP, ip.SrcIP)
	}

	if !ip.DstIP.IsGlobalUnicast() {
		return translated, fmt.Errorf("%w: IPv6 destination %s is not unicast", ErrUnsupportedDestIP, ip.DstIP)
	}

	// Guard against invalid destinations
	if !t.nat64Net.Contains(ip.DstIP) && !canUseDifferentDstIP && t.mapIPv6ToIPv4EAM(ip.DstIP) == nil {
		return translated, fmt.Errorf("%w: IPv6 destination %s is not mappable", ErrInvalidPacket, ip.DstIP)
	}

	dstIP := translated.DstIP

	ttl := t.decrementHopLimit(ip.HopLimit)
	if overrides.QuotedPacket == true {
		// For quoted packets, we do not decrement the TTL/Hop Limit, as it is already decremented in the outer packet.
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
		SrcIP:      translated.SrcIP,
		DstIP:      dstIP,
	}

	var payload []byte
	var dropped bool

	switch protocol {
	case layers.IPProtocolICMPv4:
		payload, dropped = t.translateICMPv6(sanitizedPayload)
	case layers.IPProtocolTCP:
		payload = t.translateTCPv6(ipv4, sanitizedPayload)
	case layers.IPProtocolUDP:
		payload = t.translateUDPv6(ipv4, sanitizedPayload)
	case layers.IPProtocolIPv6Fragment:
		fragmentLayer := packet.Layer(layers.LayerTypeIPv6Fragment)
		if fragmentLayer == nil {
			// Invalid packet, drop
			log.Printf("Dropping invalid fragmented IPv6 packet without any actual fragment in it")
			return translated, fmt.Errorf("%w: IPv6 fragments are unsupported", ErrUnsupportedProtocol)
		}

		fragment, _ := fragmentLayer.(*layers.IPv6Fragment)
		// RFC 8200 Section 4.5 requires an M=1 fragment's payload to be an
		// integer multiple of 8 octets. Reserved fields are ignored on reception.
		if fragment == nil {
			return translated, fmt.Errorf("%w: missing IPv6 fragment header", ErrInvalidPacket)
		}

		if len(fragment.Contents) < 8 || (fragment.MoreFragments && len(fragment.Payload)%8 != 0) {
			return translated, fmt.Errorf("%w: invalid IPv6 fragment", ErrInvalidPacket)
		}
		if fragment.NextHeader == layers.IPProtocolICMPv6 {
			return translated, fmt.Errorf("%w: fragmented ICMPv6 packets are unsupported", ErrUnsupportedProtocol)
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
			return translated, nil
		}
	default:
		// Unknown protocols are forwarded as opaque payloads.
		payload = sanitizedPayload
	}
	if dropped {
		return translated, nil
	}

	if payload == nil {
		if protocol == layers.IPProtocolICMPv4 {
			return translated, ErrInvalidICMP
		}
		return translated, fmt.Errorf("%w: IPv6 protocol %d payload", ErrInvalidPacket, protocol)
	}

	result := t.serializeTranslatedPacket(ipv4.SrcIP, ipv4.DstIP, ipv4, gopacket.Payload(payload))
	if result.Packet == nil {
		return result, fmt.Errorf("%w: failed to serialize IPv4 packet", ErrInvalidPacket)
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
