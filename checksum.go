package siit

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func validIPv4HeaderChecksum(ip *layers.IPv4) bool {
	original := ip.Checksum
	copy := *ip
	buffer := gopacket.NewSerializeBuffer()

	if err := copy.SerializeTo(buffer, gopacket.SerializeOptions{ComputeChecksums: true}); err != nil {
		return false
	}

	return copy.Checksum == original
}

func validTransportChecksum(network gopacket.NetworkLayer, protocol layers.IPProtocol, payload []byte) bool {
	layerType := transportLayerType(protocol)
	decoded := gopacket.NewPacket(payload, layerType, gopacket.Default)
	buffer := gopacket.NewSerializeBuffer()

	switch protocol {
	case layers.IPProtocolTCP:
		if len(payload) < transportHeaderLength(protocol) {
			return false
		}

		transport, ok := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || transport.SetNetworkLayerForChecksum(network) != nil {
			return false
		}

		original := transport.Checksum
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true}, transport, gopacket.Payload(transport.Payload)); err != nil {
			return false
		}

		return transport.Checksum == original
	case layers.IPProtocolUDP:
		if len(payload) < transportHeaderLength(protocol) {
			return false
		}

		transport, ok := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			return false
		}

		// RFC 768 Section 3: IPv4 UDP may omit its checksum.
		if network.LayerType() == layers.LayerTypeIPv4 && transport.Checksum == 0 {
			return true
		} else if transport.Checksum == 0 {
			return false
		}

		if transport.SetNetworkLayerForChecksum(network) != nil {
			return false
		}

		original := transport.Checksum
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true}, transport, gopacket.Payload(transport.Payload)); err != nil {
			return false
		}

		return transport.Checksum == original
	case layers.IPProtocolICMPv4:
		if len(payload) < 8 {
			return false
		}

		transport, ok := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			return false
		}

		original := transport.Checksum
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true}, transport, gopacket.Payload(transport.Payload)); err != nil {
			return false
		}

		return transport.Checksum == original
	case layers.IPProtocolICMPv6:
		if len(payload) < 8 {
			return false
		}

		transport, ok := decoded.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		if !ok || transport.SetNetworkLayerForChecksum(network) != nil {
			return false
		}

		original := transport.Checksum
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true}, transport, gopacket.Payload(transport.Payload)); err != nil {
			return false
		}

		return transport.Checksum == original
	default:
		return true
	}
}

func isZeroUDPChecksum(payload []byte, protocol layers.IPProtocol) bool {
	if protocol != layers.IPProtocolUDP || len(payload) < 8 {
		return false
	}

	decoded := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)
	udp, ok := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
	return ok && udp.Checksum == 0
}

func transportLayerType(protocol layers.IPProtocol) gopacket.LayerType {
	switch protocol {
	case layers.IPProtocolUDP:
		return layers.LayerTypeUDP
	case layers.IPProtocolICMPv4:
		return layers.LayerTypeICMPv4
	case layers.IPProtocolICMPv6:
		return layers.LayerTypeICMPv6
	default:
		return layers.LayerTypeTCP
	}
}

func shouldValidateICMPv6(payload []byte) bool {
	if len(payload) == 0 {
		return true
	}

	switch payload[0] {
	case layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage,
		layers.ICMPv6TypeMLDv1MulticastListenerReportMessage,
		layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage,
		layers.ICMPv6TypeRouterSolicitation,
		layers.ICMPv6TypeRouterAdvertisement,
		layers.ICMPv6TypeNeighborSolicitation,
		layers.ICMPv6TypeNeighborAdvertisement,
		layers.ICMPv6TypeRedirect:
		return false
	default:
		return true
	}
}
