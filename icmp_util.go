package siit

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	icmpErrorQuoteLength        = 8
	icmpErrorHeaderLength       = 8
	ipv4ICMPErrorPayloadMaximum = ipv4MinimumMTU - ipv4HeaderLength - icmpErrorHeaderLength
	ipv6ICMPErrorPayloadMaximum = ipv6MinimumMTU - ipv6HeaderLength - icmpErrorHeaderLength
)

// Mappings based on Figures 3 and 6 in RFC 7915.
var parameterPointerMappings = []struct {
	ipv4Start uint32
	ipv4End   uint32
	ipv6Start uint32
	ipv6End   uint32
}{
	{0, 0, 0, 0},     // Version/IHL <-> Version/Traffic Class.
	{1, 1, 1, 1},     // Type of Service <-> Traffic Class/Flow Label.
	{2, 3, 4, 5},     // Total Length <-> Payload Length.
	{8, 8, 7, 7},     // Time to Live <-> Hop Limit.
	{9, 9, 6, 6},     // Protocol <-> Next Header.
	{12, 15, 8, 23},  // Source Address <-> Source Address.
	{16, 19, 24, 39}, // Destination Address <-> Destination Address.
}

func (t *Translator) mapParameterPointer(pointer uint32, ipv4ToIPv6 bool) (uint32, bool) {
	for _, mapping := range parameterPointerMappings {
		if ipv4ToIPv6 {
			if pointer >= mapping.ipv4Start && pointer <= mapping.ipv4End {
				return mapping.ipv6Start, true
			}
			continue
		}

		if pointer >= mapping.ipv6Start && pointer <= mapping.ipv6End {
			return mapping.ipv4Start, true
		}
	}
	return 0, false
}

// newICMPv4 builds a message from Type, Code, Checksum, the four octets of the rest of the header and the data (RFC 792).
func newICMPv4(icmpType, code byte, rest uint32, data []byte) []byte {
	message := append(binary.BigEndian.AppendUint32([]byte{icmpType, code, 0, 0}, rest), data...)
	binary.BigEndian.PutUint16(message[2:], internetChecksum(message))
	return message
}

// newICMPv6 is like newICMPv4, but the checksum covers the pseudo-header of the IPv6 packet (RFC 4443 Section 2.3).
func newICMPv6(ip *layers.IPv6, icmpType, code byte, rest uint32, data []byte) []byte {
	message := append(binary.BigEndian.AppendUint32([]byte{icmpType, code, 0, 0}, rest), data...)
	pseudoHeader := ipv6PseudoHeader(ip.SrcIP, ip.DstIP, layers.IPProtocolICMPv6, len(message))
	binary.BigEndian.PutUint16(message[2:], internetChecksum(pseudoHeader, message))
	return message
}

// translateQuotedIPv4 translates the packet quoted in an ICMPv4 error (RFC 7915 Section 4.3), nil if it is dropped.
func (t *Translator) translateQuotedIPv4(data []byte) []byte {
	translated, err := t.TranslateIPv4(gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default), TranslationOverrides{QuotedPacket: true})
	if err != nil {
		return nil
	}

	return translated.Packet
}

// translateQuotedIPv6 translates the packet quoted in an ICMPv6 error (RFC 7915 Section 5.3), nil if it is dropped.
func (t *Translator) translateQuotedIPv6(data []byte) []byte {
	translated, err := t.TranslateIPv6(gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default), TranslationOverrides{QuotedPacket: true})
	if err != nil {
		return nil
	}

	return translated.Packet
}
