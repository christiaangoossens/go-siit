package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// Two hosts with an Explicit Address Mapping, so that the translated pseudo-header differs from the Well-Known Prefix one.
	eamHost1 = net.ParseIP("2001:db8::10")
	eamHost2 = net.ParseIP("2001:db8::20")
	eamTable = siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
		{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::20/128"},
	}
)

// RFC 7915 Sections 4.5 and 5.5 (MUST): the transport checksum is updated for the changed pseudo-header (and for
// ICMP the dropped or added pseudo-header, Sections 4.2 and 5.2), whichever addresses the mapping produces.
func TestTranslatedChecksumsCoverTheNewPseudoHeader(t *testing.T) {
	mappings := []struct {
		name       string
		translator *siit.Translator
		v6Source   net.IP // IPv6 address of the host that owns ipv4Source
		v6Dest     net.IP // IPv6 address of the host that owns ipv4Dest
	}{
		{name: "Well-Known Prefix", translator: testTranslator(), v6Source: ipv4TranslatedSource, v6Dest: ipv4TranslatedDest},
		{name: "EAM", translator: testTranslatorWithEAM(eamTable), v6Source: eamHost1, v6Dest: eamHost2},
	}
	for _, mapping := range mappings {
		for _, kind := range []string{segmentTCP, segmentUDP, segmentICMP} {
			t.Run(mapping.name+"/"+kind+"/IPv4 to IPv6", func(t *testing.T) {
				input := ipv4Segment(t, kind, ipv4Source, ipv4Dest, defaultTTL)
				result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
					return mapping.translator.TranslateIPv4(input, siit.TranslationOverrides{})
				})
				packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
				ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				if !ip.SrcIP.Equal(mapping.v6Source) || !ip.DstIP.Equal(mapping.v6Dest) {
					t.Fatalf("addresses %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, mapping.v6Source, mapping.v6Dest)
				}
				requireValidIPv6Checksum(t, packet, ip)
			})
			t.Run(mapping.name+"/"+kind+"/IPv6 to IPv4", func(t *testing.T) {
				input := ipv6Segment(t, kind, mapping.v6Source, mapping.v6Dest, defaultTTL)
				result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
					return mapping.translator.TranslateIPv6(input, siit.TranslationOverrides{})
				})
				packet := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
				ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if !ip.SrcIP.Equal(ipv4Source) || !ip.DstIP.Equal(ipv4Dest) {
					t.Fatalf("addresses %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, ipv4Source, ipv4Dest)
				}
				requireValidIPv4Checksum(t, packet, ip)
			})
		}
	}
}

func requireValidIPv6Checksum(t *testing.T, packet gopacket.Packet, ip *layers.IPv6) {
	t.Helper()
	switch {
	case packet.Layer(layers.LayerTypeTCP) != nil:
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !bytes.Equal(tcp.Payload, segmentPayload) || tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) {
			t.Fatalf("TCP checksum %#x does not match the IPv6 pseudo-header", tcp.Checksum)
		}
	case packet.Layer(layers.LayerTypeUDP) != nil:
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !bytes.Equal(udp.Payload, segmentPayload) || udp.Checksum == 0 || udp.Checksum != recalculatedUDPChecksum(t, ip, udp) {
			t.Fatalf("UDP checksum %#x does not match the IPv6 pseudo-header", udp.Checksum)
		}
	case packet.Layer(layers.LayerTypeICMPv6) != nil:
		icmp := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		if icmp.TypeCode.Type() != layers.ICMPv6TypeEchoRequest || icmp.Checksum != recalculatedICMPv6Checksum(t, ip, icmp) {
			t.Fatalf("ICMPv6 checksum %#x does not match the IPv6 pseudo-header", icmp.Checksum)
		}
	default:
		t.Fatalf("translated packet has no transport layer: %v", packet.ErrorLayer())
	}
}

func requireValidIPv4Checksum(t *testing.T, packet gopacket.Packet, ip *layers.IPv4) {
	t.Helper()
	if ip.Checksum != ipv4HeaderChecksum(ip) {
		t.Fatalf("IPv4 header checksum %#x is invalid", ip.Checksum)
	}
	switch {
	case packet.Layer(layers.LayerTypeTCP) != nil:
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !bytes.Equal(tcp.Payload, segmentPayload) || tcp.Checksum != recalculatedTCPChecksum(t, ip, tcp) {
			t.Fatalf("TCP checksum %#x does not match the IPv4 pseudo-header", tcp.Checksum)
		}
	case packet.Layer(layers.LayerTypeUDP) != nil:
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !bytes.Equal(udp.Payload, segmentPayload) || udp.Checksum != recalculatedUDPChecksum(t, ip, udp) {
			t.Fatalf("UDP checksum %#x does not match the IPv4 pseudo-header", udp.Checksum)
		}
	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if icmp.TypeCode.Type() != echoRequest || icmp.Checksum != recalculatedICMPv4Checksum(t, icmp) {
			t.Fatalf("ICMPv4 checksum %#x is invalid", icmp.Checksum)
		}
	default:
		t.Fatalf("translated packet has no transport layer: %v", packet.ErrorLayer())
	}
}

// Local robustness: the IPv4 header checksum and the transport checksum (TCP, UDP, ICMP) are verified before
// translating, because RFC 7915 Sections 4.5 and 5.5 only require updating a checksum, which would hide a
// corrupt packet. A packet that fails verification is rejected with ErrInvalidPacket and not translated.
func TestTranslateRejectsInvalidChecksums(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		v4     bool
		kind   string
	}{
		{name: "IPv4 header", offset: ipv4ChecksumOffset, v4: true, kind: segmentTCP},
		{name: "IPv4 TCP", offset: ipv4HeaderLength + 16, v4: true, kind: segmentTCP},
		{name: "IPv4 UDP", offset: ipv4HeaderLength + 6, v4: true, kind: segmentUDP},
		{name: "IPv4 ICMP", offset: ipv4HeaderLength + icmpChecksumOffset, v4: true, kind: segmentICMP},
		{name: "IPv6 TCP", offset: ipv6HeaderLength + 16, kind: segmentTCP},
		{name: "IPv6 UDP", offset: ipv6HeaderLength + 6, kind: segmentUDP},
		{name: "IPv6 ICMP", offset: ipv6HeaderLength + icmpChecksumOffset, kind: segmentICMP},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Flip a bit instead of zeroing so that an IPv4 UDP checksum is invalid rather than absent.
			var result siit.TranslatedPacket
			var err error
			if test.v4 {
				data := append([]byte(nil), ipv4Segment(t, test.kind, ipv4Source, ipv4Dest, defaultTTL).Data()...)
				data[test.offset] ^= 0x10
				result, err = testTranslator().TranslateIPv4(gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default), siit.TranslationOverrides{})
				if !result.SrcIP.Equal(ipv4TranslatedSource) || !result.DstIP.Equal(ipv4TranslatedDest) {
					t.Fatalf("metadata was not preserved: %s -> %s", result.SrcIP, result.DstIP)
				}
			} else {
				data := append([]byte(nil), ipv6Segment(t, test.kind, ipv6Source, ipv6Dest, defaultTTL).Data()...)
				data[test.offset] ^= 0x10
				result, err = testTranslator().TranslateIPv6(gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default), siit.TranslationOverrides{})
				if !result.SrcIP.Equal(ipv6TranslatedSource) || !result.DstIP.Equal(ipv6TranslatedDest) {
					t.Fatalf("metadata was not preserved: %s -> %s", result.SrcIP, result.DstIP)
				}
			}
			if !errors.Is(err, siit.ErrInvalidPacket) || result.Packet != nil {
				t.Fatalf("packet with an invalid %s checksum was not rejected: err=%v", test.name, err)
			}
		})
	}
}

func zeroUDPChecksum(t *testing.T, packet gopacket.Packet, headerLength int) []byte {
	t.Helper()
	data := append([]byte(nil), packet.Data()...)
	binary.BigEndian.PutUint16(data[udpChecksumOffset(headerLength):], 0)
	return data
}

// RFC 7915 Section 5.5 (MUST) with RFC 8200 Section 8.1: an IPv6 UDP packet with a zero checksum is invalid
// and silently dropped.
func TestTranslateIPv6ZeroChecksumUDPDropsPacket(t *testing.T) {
	data := zeroUDPChecksum(t, ipv6Segment(t, segmentUDP, ipv6Source, ipv6Dest, defaultTTL), ipv6HeaderLength)
	result, err := testTranslator().TranslateIPv6(gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default), siit.TranslationOverrides{})
	requireDropped(t, result, err)
}

// RFC 7915 Section 4.5 (MUST) with RFC 768: an unfragmented IPv4 UDP datagram without a checksum is
// translated with a newly computed IPv6 checksum (the first of the two permitted behaviours; the other, dropping
// the packet, is not implemented, see the README).
func TestTranslateIPv4ZeroChecksumUDPGetsComputedChecksum(t *testing.T) {
	data := zeroUDPChecksum(t, ipv4Segment(t, segmentUDP, ipv4Source, ipv4Dest, defaultTTL), ipv4HeaderLength)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default), siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	requireValidIPv6Checksum(t, packet, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6))
}
