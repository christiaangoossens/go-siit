package siit

import (
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
	ErrInvalidPacket          = errors.New("Invalid packet")
	ErrInvalidICMP            = errors.New("Invalid ICMP packet")
	ErrUnsupportedProtocol    = errors.New("Unsupported protocol")
	ErrICMPTranslationMissing = errors.New("ICMP translation is not implemented")
	ErrTimeExceeded           = errors.New("TTL or Hop Limit expired")
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

func serializePacket(layers ...gopacket.SerializableLayer) []byte {
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
	if ip.TTL <= 1 {
		packet := t.generateIPv6TimeExceeded(ip)
		return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet}
	}
	protocol := ip.Protocol
	if protocol == layers.IPProtocolIGMP {
		return nil, nil
	}

	if protocol == layers.IPProtocolICMPv4 {
		protocol = layers.IPProtocolICMPv6
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

	ttl := decrementHopLimit(ip.TTL)
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

	switch protocol {
	case layers.IPProtocolICMPv6:
		payload, dropped = translateICMPv4(ipv6, ip.Payload)
	case layers.IPProtocolTCP:
		payload = translateTCPv4(ipv6, ip.Payload)
	case layers.IPProtocolUDP:
		payload = translateUDPv4(ipv6, ip.Payload)
	default:
		return nil, fmt.Errorf("%w: IPv4 protocol %d", ErrUnsupportedProtocol, protocol)
	}
	if dropped {
		return nil, nil
	}

	// Occurs when payload too short or malformed, truncated, or unsupported ICMP type
	if payload == nil {
		if protocol == layers.IPProtocolICMPv6 {
			if len(ip.Payload) < 8 {
				return nil, ErrInvalidICMP
			}
			return nil, ErrICMPTranslationMissing
		}
		return nil, fmt.Errorf("%w: IPv4 protocol %d payload", ErrInvalidPacket, protocol)
	}
	result := serializePacket(ipv6, gopacket.Payload(payload))
	if result == nil {
		return nil, fmt.Errorf("%w: failed to serialize IPv6 packet", ErrInvalidPacket)
	}
	return result, nil
}

func translateICMPv4(ip *layers.IPv6, payload []byte) ([]byte, bool) {
	if len(payload) < 8 {
		return nil, false
	}

	// Manually parsing ICMPv4
	icmpv4Type := payload[0] // Type
	icmpv4Code := payload[1] // Code (not used in translation)
	// Checksum is at bytes [2:4], generally skipped for just translating
	identifier := (uint16(payload[4]) << 8) | uint16(payload[5])
	sequence := (uint16(payload[6]) << 8) | uint16(payload[7])

	// Extract payload data after ICMPv4 header
	icmpv4Payload := payload[8:]

	var newType uint8
	switch icmpv4Type {
	case 8:
		if icmpv4Code != 0 {
			return nil, false
		}
		newType = 128
	case 0:
		if icmpv4Code != 0 {
			return nil, false
		}
		newType = 129
	case 3:
		if icmpv4Code == 14 || icmpv4Code > 15 {
			log.Printf("Dropping ICMPv4 Destination Unreachable code %d", icmpv4Code)
			return nil, true
		}
		log.Printf("Should generate error on our local side to transmit back: type %d, code %d, identifier %d, sequence %d", icmpv4Type, icmpv4Code, identifier, sequence)
		return nil, false
	case 4, 5, 6:
		log.Printf("Dropping ICMPv4 message type %d", icmpv4Type)
		return nil, true
	case 12:
		if icmpv4Code == 1 || icmpv4Code > 2 {
			log.Printf("Dropping ICMPv4 Parameter Problem code %d", icmpv4Code)
			return nil, true
		}
		return nil, false
	case 11:
		return nil, false
	default:
		log.Printf("Dropping ICMPv4 packet with unsupported type %d", icmpv4Type)
		return nil, true
	}

	// Create new IPv6 ICMP packet
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(newType, 0), // code is 0 for both 128 and 129,
	}

	// Set the actual id & seq
	// Create ICMPv6 Echo Message
	echoLayer := &layers.ICMPv6Echo{
		Identifier: identifier,
		SeqNumber:  sequence,
	}

	// Use the pseudoheader to calculate the checksum
	err := icmpv6.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Printf("Failed to set network layer for ICMPv6 checksum: %v", err)
		return nil, false
	}

	return serializePacket(icmpv6, echoLayer, gopacket.Payload(icmpv4Payload)), false
}

func translateTCPv4(ip *layers.IPv6, payload []byte) []byte {
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

	return serializePacket(tcp, gopacket.Payload(tcp.Payload))
}

func translateUDPv4(ip *layers.IPv6, payload []byte) []byte {
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

	return serializePacket(udp, gopacket.Payload(udp.Payload))
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
	if ip.HopLimit <= 1 {
		packet := t.generateIPv4TimeExceeded(ip)
		return packet, &TranslationError{Err: ErrTimeExceeded, Packet: packet}
	}
	protocol := ip.NextHeader

	if protocol == layers.IPProtocolICMPv6 {
		protocol = layers.IPProtocolICMPv4
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
			return nil, fmt.Errorf("%w: IPv6 destination %s is not mappable", ErrInvalidPacket, ip.DstIP)
		}
		dstIP = ip.DstIP[12:]
	}

	ttl := decrementHopLimit(ip.HopLimit)
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
		payload = translateTCPv6(ipv4, ip.Payload)
	case layers.IPProtocolUDP:
		payload = translateUDPv6(ipv4, ip.Payload)
	case layers.IPProtocolIPv6Fragment:
		fragmentLayer := packet.Layer(layers.LayerTypeIPv6Fragment)
		if fragmentLayer == nil {
			// Invalid packet, drop
			log.Printf("Dropping invalid fragmented IPv6 packet without any actual fragment in it")
			return nil, fmt.Errorf("%w: IPv6 fragments are unsupported", ErrUnsupportedProtocol)
		}

		fragment, _ := fragmentLayer.(*layers.IPv6Fragment)

		ipv4.FragOffset = fragment.FragmentOffset
		ipv4.Id = uint16(fragment.Identification)

		if fragment.MoreFragments {
			ipv4.Flags = 1 << 0 // MF flag
		}

		ipv4.Protocol = fragment.NextHeader
		payload = fragment.Payload
	default:
		return nil, fmt.Errorf("%w: IPv6 protocol %d", ErrUnsupportedProtocol, protocol)
	}
	if dropped {
		return nil, nil
	}

	if payload == nil {
		if protocol == layers.IPProtocolICMPv4 {
			if len(ip.Payload) < 8 {
				return nil, ErrInvalidICMP
			}
			return nil, ErrICMPTranslationMissing
		}
		return nil, fmt.Errorf("%w: IPv6 protocol %d payload", ErrInvalidPacket, protocol)
	}
	result := serializePacket(ipv4, gopacket.Payload(payload))
	if result == nil {
		return nil, fmt.Errorf("%w: failed to serialize IPv4 packet", ErrInvalidPacket)
	}
	return result, nil
}

func decrementHopLimit(value uint8) uint8 {
	if value == 0 {
		return 0
	}
	return value - 1
}

func (t *Translator) generateIPv6TimeExceeded(ip *layers.IPv4) []byte {
	destination := t.mapIPv4ToIPv6(ip.SrcIP)
	protocol := ip.Protocol
	if protocol == layers.IPProtocolICMPv4 {
		protocol = layers.IPProtocolICMPv6
	}
	inner := &layers.IPv6{
		Version: 6, NextHeader: protocol, HopLimit: ip.TTL,
		TrafficClass: ip.TOS, SrcIP: t.mapIPv4ToIPv6(ip.SrcIP), DstIP: t.mapIPv4ToIPv6(ip.DstIP),
	}
	innerBytes := serializePacket(inner, gopacket.Payload(ip.Payload[:min(len(ip.Payload), 8)]))
	outer := &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
		SrcIP: t.mapIPv4ToIPv6(t.ipv4RouterAddress), DstIP: destination,
	}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(3, 0)}
	if err := icmp.SetNetworkLayerForChecksum(outer); err != nil {
		return nil
	}
	return serializePacket(outer, icmp, gopacket.Payload(innerBytes))
}

func (t *Translator) generateIPv4TimeExceeded(ip *layers.IPv6) []byte {
	var destination net.IP
	if t.nat64Net.Contains(ip.SrcIP) {
		destination = ip.SrcIP[12:]
	} else {
		return nil
	}
	protocol := ip.NextHeader
	if protocol == layers.IPProtocolICMPv6 {
		protocol = layers.IPProtocolICMPv4
	}
	inner := &layers.IPv4{
		Version: 4, IHL: 5, Protocol: protocol, TTL: ip.HopLimit,
		TOS: ip.TrafficClass, SrcIP: destination, DstIP: ip.DstIP[12:],
	}
	innerBytes := serializePacket(inner, gopacket.Payload(ip.Payload[:min(len(ip.Payload), 8)]))
	outer := &layers.IPv4{
		Version: 4, IHL: 5, Protocol: layers.IPProtocolICMPv4, TTL: 64,
		SrcIP: t.ipv4RouterAddress, DstIP: destination,
	}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(11, 0)}
	return serializePacket(outer, icmp, gopacket.Payload(innerBytes))
}

func (t *Translator) translateICMPv6(dest net.IP, payload []byte) ([]byte, bool) {
	if len(payload) < 8 {
		return nil, false
	}

	// Parse the ICMP packet to get the type
	// Read ICMPv6 header fields
	icmpv6Type := payload[0]
	code := payload[1]

	switch icmpv6Type {
	case 128:
		if code != 0 {
			return nil, false
		}
		return translateICMPv6Echo(8, payload), false
	case 129:
		if code != 0 {
			return nil, false
		}
		return translateICMPv6Echo(0, payload), false
	case 1:
		// Destination Unreachable
		if code > 4 {
			log.Printf("Dropping ICMPv6 Destination Unreachable code %d", code)
			return nil, true
		}
		return t.generateICMPv6DestUnreachError(code, dest, payload), false
	case 2, 4:
		return nil, false
	case 3:
		if code > 1 {
			return nil, false
		}
		// Time Exceeded
		return t.generateICMPv6Error(11, code, dest, payload), false
	default:
		log.Printf("Dropping ICMPv6 packet with unsupported type %d", icmpv6Type)
		return nil, true
	}
}

func translateTCPv6(ip *layers.IPv4, payload []byte) []byte {
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

	return serializePacket(tcp, gopacket.Payload(tcp.Payload))
}

func translateUDPv6(ip *layers.IPv4, payload []byte) []byte {
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

	return serializePacket(udp, gopacket.Payload(udp.Payload))
}

func translateICMPv6Echo(newType byte, payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}

	identifier := (uint16(payload[4]) << 8) | uint16(payload[5])
	sequence := (uint16(payload[6]) << 8) | uint16(payload[7])
	icmpv6Payload := payload[8:]

	// Create new IPv4 ICMP packet
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(newType, 0), // code is 0 for both 8 and 0,
		Id:       identifier,
		Seq:      sequence,
	}

	return serializePacket(icmpv4, gopacket.Payload(icmpv6Payload))
}

func (t *Translator) generateICMPv6DestUnreachError(code byte, dest net.IP, payload []byte) []byte {
	var newCode byte

	switch code {
	case 0:
		//  Code 0 (No route to destination):  Set the Code to 1 (Host unreachable).
		newCode = 1
	case 1:
		// Code 1 (Communication with destination administratively prohibited):  Set the Code to 10 (Communication with destination host administratively prohibited).
		newCode = 10
	case 2:
		//  Code 2 (Beyond scope of source address):  Set the Code to 1 (Host unreachable).
		newCode = 1
	case 3:
		// Code 3 (Address unreachable):  Set the Code to 1 (Host unreachable).
		newCode = 1
	case 4:
		//  Code 4 (Port unreachable):  Set the Code to 3 (Port unreachable).
		newCode = 3
	default:
		// Other Code values:  Silently drop.
		return nil
	}

	// Create new IPv4 ICMP packet
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(3, newCode),
	}

	return serializePacket(icmpv4, gopacket.Payload(t.generateICMPv6ErrorData(dest, payload)))
}

func (t *Translator) generateICMPv6Error(typeNr byte, code byte, dest net.IP, payload []byte) []byte {
	// Create new IPv4 ICMP packet
	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(typeNr, code),
	}

	return serializePacket(icmpv4, gopacket.Payload(t.generateICMPv6ErrorData(dest, payload)))
}

func (t *Translator) generateICMPv6ErrorData(dest net.IP, payload []byte) []byte {
	innerPacket := gopacket.NewPacket(payload[8:], layers.LayerTypeIPv6, gopacket.Default)
	innerPacketPayload, err := t.TranslateIPv6(innerPacket, TranslationOverrides{
		// Reverse the packet direction for the inner packet
		SourceIP: dest,
		// Do not decrement the TTL for the inner packet, as it is part of the error message
		PreventTTLDecrement: true,
	})
	if err != nil {
		return nil
	}

	// ICMPv4 error packets cannot exceed 576 bytes
	maxlength := 576 - 20 - 8

	return innerPacketPayload[:min(len(innerPacketPayload), maxlength)]
}
