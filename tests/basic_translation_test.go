package siit_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.1 and 5.1 (MUST): the IP header fields are translated. Version, header length, Total Length /
// Payload Length and protocol follow from the new header; the TTL / Hop Limit is decremented by one; the
// Traffic Class and TOS (including the ECN bits) are copied (RFC 7915 "SHOULD ignore", see the README); the Flow
// Label is zero towards IPv6; and an IPv6 packet of at most 1260 octets (IPv4 length) clears DF, a larger one sets it (RFC 7915 Section 5.1). The DF bit of an unfragmented IPv4 packet
// does not produce a Fragment header.
func TestTranslateIPHeaderFields(t *testing.T) {
	for _, tos := range []uint8{0, 0x2e << 2, 0x03, 0xff} {
		for _, ttl := range []uint8{2, defaultTTL, 255} {
			t.Run(fmt.Sprintf("IPv4 to IPv6 TOS %#x TTL %d", tos, ttl), func(t *testing.T) {
				input := withTOS(t, ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, ttl), tos)
				data := input.Data()
				result := translateIPv4Raw(t, data)
				ip := result.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				if ip.TrafficClass != tos || ip.FlowLabel != 0 || ip.HopLimit != ttl-1 || ip.NextHeader != layers.IPProtocolTCP || ip.Version != 6 {
					t.Fatalf("unexpected IPv6 header: %+v", ip)
				}
				if int(ip.Length) != len(data)-ipv4HeaderLength || !ip.SrcIP.Equal(ipv4TranslatedSource) || !ip.DstIP.Equal(ipv4TranslatedDest) {
					t.Fatalf("unexpected IPv6 length or addresses: %+v", ip)
				}
			})
			t.Run(fmt.Sprintf("IPv6 to IPv4 traffic class %#x hop limit %d", tos, ttl), func(t *testing.T) {
				data := append([]byte(nil), ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, ttl).Data()...)
				data[0], data[1] = 0x60|tos>>4, data[1]&0x0f|tos<<4
				result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
					return testTranslator().TranslateIPv6(gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default), siit.TranslationOverrides{})
				})
				ip := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if ip.TOS != tos || ip.TTL != ttl-1 || ip.Protocol != layers.IPProtocolTCP || ip.IHL != 5 || ip.Flags != 0 || ip.FragOffset != 0 {
					t.Fatalf("unexpected IPv4 header: %+v", ip)
				}
				if int(ip.Length) != len(result) || ip.Checksum != ipv4HeaderChecksum(ip) || !ip.SrcIP.Equal(ipv6TranslatedSource) || !ip.DstIP.Equal(ipv6TranslatedDest) {
					t.Fatalf("unexpected IPv4 length, checksum or addresses: %+v", ip)
				}
			})
		}
	}

	for _, test := range []struct {
		name       string
		payloadLen int
		wantDF     bool
	}{
		{name: "at threshold", payloadLen: maxIPv4PacketLength - ipv4HeaderLength, wantDF: false},
		{name: "above threshold", payloadLen: maxIPv4PacketLength + 1 - ipv4HeaderLength, wantDF: true},
		{name: "minimum", payloadLen: 8, wantDF: false},
	} {
		t.Run("IPv6 to IPv4 DF "+test.name, func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolGRE, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(bytes.Repeat([]byte{0xab}, test.payloadLen))), layers.LayerTypeIPv6, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			})
			translated := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if gotDF := translated.Flags&layers.IPv4DontFragment != 0; gotDF != test.wantDF || translated.Length != uint16(ipv4HeaderLength+test.payloadLen) {
				t.Fatalf("unexpected IPv4 size/DF: length=%d DF=%t", translated.Length, gotDF)
			}
		})
	}

	// The DF bit of an unfragmented IPv4 packet has no IPv6 equivalent: neither value produces a Fragment header.
	for _, flags := range []layers.IPv4Flag{0, layers.IPv4DontFragment} {
		t.Run(fmt.Sprintf("IPv4 to IPv6 flags %v", flags), func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Id: 0x1234, Flags: flags, Protocol: layers.IPProtocolGRE, SrcIP: ipv4Source, DstIP: ipv4Dest}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(make([]byte, 16))), layers.LayerTypeIPv4, gopacket.Default)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			})
			if translated := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6); translated.NextHeader != layers.IPProtocolGRE || len(result) != ipv6HeaderLength+16 {
				t.Fatalf("unfragmented packet was translated with a Fragment header: %+v", translated)
			}
		})
	}
}

func translateIPv4Raw(t *testing.T, data []byte) gopacket.Packet {
	t.Helper()
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default), siit.TranslationOverrides{})
	})
	return gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
}

// RFC 7915 Sections 4.5 and 5.5 (MUST): TCP and UDP payloads of empty, odd, even and large lengths, and TCP options,
// survive a translation in each direction and keep a valid checksum for the new pseudo-header.
func TestTranslateTransportPayloads(t *testing.T) {
	mss := []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}}
	wscale := []layers.TCPOption{{OptionType: layers.TCPOptionKindNop, OptionLength: 1}, {OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}}
	for _, payload := range [][]byte{nil, {0x01}, {0x01, 0x02}, bytes.Repeat([]byte{0xfe}, 1001)} {
		for name, options := range map[string][]layers.TCPOption{"no options": nil, "MSS": mss, "NOP and window scale": wscale} {
			t.Run(fmt.Sprintf("TCP %d octets %s", len(payload), name), func(t *testing.T) {
				v6 := translateIPv4Raw(t, ipv4TCPPayloadPacket(t, payload, options).Data())
				ip6 := v6.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				tcp6, ok := v6.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if !ok || !bytes.Equal(tcp6.Payload, payload) || len(tcp6.Options) != len(options) || tcp6.Checksum != recalculatedTCPChecksum(t, ip6, tcp6) {
					t.Fatalf("TCP segment changed towards IPv6: %v", v6.ErrorLayer())
				}
				v4 := translateToIPv4Packet(t, ipv6TCPPayloadPacketWithOptions(t, payload, options))
				ip4 := v4.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				tcp4, ok := v4.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if !ok || !bytes.Equal(tcp4.Payload, payload) || len(tcp4.Options) != len(options) || tcp4.Checksum != recalculatedTCPChecksum(t, ip4, tcp4) {
					t.Fatalf("TCP segment changed towards IPv4: %v", v4.ErrorLayer())
				}
				for index, option := range options {
					if tcp6.Options[index].OptionType != option.OptionType || !bytes.Equal(tcp6.Options[index].OptionData, option.OptionData) ||
						tcp4.Options[index].OptionType != option.OptionType || !bytes.Equal(tcp4.Options[index].OptionData, option.OptionData) {
						t.Fatalf("TCP option %d was not preserved", index)
					}
				}
			})
		}
		t.Run(fmt.Sprintf("UDP %d octets", len(payload)), func(t *testing.T) {
			v6 := translateIPv4Raw(t, ipv4UDPPacket(t, payload).Data())
			ip6 := v6.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			udp6, ok := v6.Layer(layers.LayerTypeUDP).(*layers.UDP)
			if !ok || !bytes.Equal(udp6.Payload, payload) || udp6.Checksum == 0 || udp6.Checksum != recalculatedUDPChecksum(t, ip6, udp6) {
				t.Fatalf("UDP datagram changed towards IPv6: %v", v6.ErrorLayer())
			}
			v4 := translateToIPv4Packet(t, ipv6UDPPayloadPacket(t, payload))
			ip4 := v4.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			udp4, ok := v4.Layer(layers.LayerTypeUDP).(*layers.UDP)
			if !ok || !bytes.Equal(udp4.Payload, payload) || udp4.Checksum == 0 || udp4.Checksum != recalculatedUDPChecksum(t, ip4, udp4) {
				t.Fatalf("UDP datagram changed towards IPv4: %v", v4.ErrorLayer())
			}
		})
	}
}

func translateToIPv4Packet(t *testing.T, input gopacket.Packet) gopacket.Packet {
	t.Helper()
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	})
	return gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
}

// Local packet-size contract (README): the translator never fragments, so a packet that fits the IPv6 MTU after
// translation is translated to a full-size packet and a larger one is rejected with ErrPacketOversized, whether or not
// it has the Don't Fragment bit (RFC 7915 Section 4.1 asks for fragmentation or a Fragmentation Needed error, which
// the README lists as unsupported). An unfragmented IPv4 packet may be MTU-20 octets, an already fragmented one
// MTU-28 octets because of the extra IPv6 Fragment header.
func TestTranslateEnforcesMTU(t *testing.T) {
	for _, mtu := range []uint32{1280, 1500, 9000} {
		for _, test := range []struct {
			name       string
			size       int // IPv4 total length
			fragmented bool
			dontFrag   bool
			wantError  bool
		}{
			{name: "maximum packet", size: int(mtu) - 20},
			{name: "maximum packet with DF", size: int(mtu) - 20, dontFrag: true},
			{name: "oversized packet", size: int(mtu) - 19, wantError: true},
			{name: "oversized packet with DF", size: int(mtu) - 19, dontFrag: true, wantError: true},
			{name: "maximum fragment", size: int(mtu) - 28, fragmented: true},
			{name: "oversized fragment", size: int(mtu) - 27, fragmented: true, wantError: true},
		} {
			t.Run(fmt.Sprintf("MTU %d %s", mtu, test.name), func(t *testing.T) {
				ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolUDP, SrcIP: ipv4Source, DstIP: ipv4Dest}
				if test.dontFrag {
					ip.Flags = layers.IPv4DontFragment
				}
				var input gopacket.Packet
				if test.fragmented {
					ip.Flags = layers.IPv4MoreFragments
					input = gopacket.NewPacket(serializeTestPacket(t, ip, gopacket.Payload(bytes.Repeat([]byte{0xab}, test.size-ipv4HeaderLength))), layers.LayerTypeIPv4, gopacket.Default)
				} else {
					udp := &layers.UDP{SrcPort: testSourcePort, DstPort: testUDPDestinationPort}
					if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
						t.Fatal(err)
					}
					payload := bytes.Repeat([]byte{0xab}, test.size-ipv4HeaderLength-udpHeaderLength)
					input = gopacket.NewPacket(serializeTestPacket(t, ip, udp, gopacket.Payload(payload)), layers.LayerTypeIPv4, gopacket.Default)
				}
				result, err := translatorWithMTU(t, mtu).TranslateIPv4(input, siit.TranslationOverrides{})
				if test.wantError {
					if !errors.Is(err, siit.ErrPacketOversized) || result.Packet != nil {
						t.Fatalf("oversized IPv4 packet was not rejected with ErrPacketOversized: result length=%d err=%v", len(result.Packet), err)
					}
					return
				}
				if err != nil || len(result.Packet) != int(mtu) {
					t.Fatalf("maximum IPv4 packet was not translated to a full-size IPv6 packet: result length=%d err=%v", len(result.Packet), err)
				}
			})
		}
	}
}

// Local configuration contract (README): an MTU below the IPv6 minimum of 1280 is rejected at creation.
func TestNewTranslatorWithMTURejectsValuesBelowIPv6Minimum(t *testing.T) {
	_, nat64Net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}
	for _, mtu := range []uint32{0, 68, 1279} {
		if _, err := siit.NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, nil, mtu); !errors.Is(err, siit.ErrInvalidMTU) {
			t.Fatalf("MTU %d: got error %v, want ErrInvalidMTU", mtu, err)
		}
	}
	if _, err := siit.NewTranslatorWithMTU(nat64Net, ipv4RouterAddress, nil, 1280); err != nil {
		t.Fatalf("the IPv6 minimum MTU was rejected: %v", err)
	}
}
