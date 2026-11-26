package siit

import (
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet is a serialized IP packet, starting at the IP header. It is empty when nothing has to be sent.
type Packet []byte

// Version returns the IP version of the packet: 4, 6, or 0 when it is empty or neither.
func (p Packet) Version() int {
	if len(p) == 0 {
		return 0
	}

	switch version := int(p[0] >> 4); version {
	case 4, 6:
		return version
	}

	return 0
}

// Src returns the source address from the IP header, or the zero Addr when the header is incomplete.
func (p Packet) Src() netip.Addr {
	switch {
	case p.Version() == 4 && len(p) >= ipv4HeaderLength:
		return netip.AddrFrom4([4]byte(p[12:16]))
	case p.Version() == 6 && len(p) >= ipv6HeaderLength:
		return netip.AddrFrom16([16]byte(p[8:24]))
	}

	return netip.Addr{}
}

// Dst returns the destination address from the IP header, or the zero Addr when the header is incomplete.
func (p Packet) Dst() netip.Addr {
	switch {
	case p.Version() == 4 && len(p) >= ipv4HeaderLength:
		return netip.AddrFrom4([4]byte(p[16:20]))
	case p.Version() == 6 && len(p) >= ipv6HeaderLength:
		return netip.AddrFrom16([16]byte(p[24:40]))
	}

	return netip.Addr{}
}

// Decode returns a lazily decoded gopacket view of the packet, or nil when Version is 0. The view shares the bytes of
// p, so p must not be modified while it is used, and it is not safe for concurrent use.
func (p Packet) Decode() gopacket.Packet {
	options := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	switch p.Version() {
	case 4:
		return gopacket.NewPacket(p, layers.LayerTypeIPv4, options)
	case 6:
		return gopacket.NewPacket(p, layers.LayerTypeIPv6, options)
	}

	return nil
}
