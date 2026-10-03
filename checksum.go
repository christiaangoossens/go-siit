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
		transport, ok := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || decoded.ErrorLayer() != nil || transport.SetNetworkLayerForChecksum(network) != nil {
			return false
		}

		original := transport.Checksum
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true}, transport, gopacket.Payload(transport.Payload)); err != nil {
			return false
		}

		return transport.Checksum == original
	case layers.IPProtocolUDP:
		transport, ok := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || decoded.ErrorLayer() != nil || (network.LayerType() == layers.LayerTypeIPv6 && transport.Checksum == 0) || transport.SetNetworkLayerForChecksum(network) != nil {
			return false
		}

		return true
	case layers.IPProtocolICMPv4:
		transport, ok := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok || decoded.ErrorLayer() != nil {
			return false
		}

		original := transport.Checksum
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true}, transport, gopacket.Payload(transport.Payload)); err != nil {
			return false
		}

		return transport.Checksum == original
	case layers.IPProtocolICMPv6:
		transport, ok := decoded.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		if !ok || decoded.ErrorLayer() != nil || transport.SetNetworkLayerForChecksum(network) != nil {
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
