package siit_test

import (
	"bytes"
	"fmt"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 7915 Sections 4.2 and 5.2 (MUST): Echo Request and Reply are translated in both directions, keeping
// Identifier, Sequence Number and data, with the ICMPv6 pseudo-header added or dropped in the checksum
// (Sections 4.5 and 5.5; the checksum values themselves are covered in checksum_test.go).
func TestTranslateICMPEcho(t *testing.T) {
	tests := []struct {
		name    string
		v4Type  uint8
		v6Type  uint8
		id, seq uint16
		payload []byte
	}{
		{name: "request", v4Type: echoRequest, v6Type: layers.ICMPv6TypeEchoRequest, id: 0x1234, seq: 7, payload: []byte("echo")},
		{name: "reply", v4Type: echoReply, v6Type: layers.ICMPv6TypeEchoReply, id: 0x4321, seq: 9, payload: []byte("reply")},
		{name: "without data", v4Type: echoRequest, v6Type: layers.ICMPv6TypeEchoRequest, id: 1, seq: 0xffff},
		{name: "with a large payload", v4Type: echoReply, v6Type: layers.ICMPv6TypeEchoReply, id: 0xffff, seq: 1, payload: bytes.Repeat([]byte{0xa5}, 1200)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
			icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(test.v4Type, 0), Id: test.id, Seq: test.seq}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload(test.payload)), layers.LayerTypeIPv4, gopacket.Default)
			v6 := translateToICMPv6(t, testTranslator(), input)
			echo, ok := v6.packet.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
			if v6.icmp.TypeCode.Type() != test.v6Type || v6.icmp.TypeCode.Code() != 0 || !ok || echo.Identifier != test.id || echo.SeqNumber != test.seq || !bytes.HasSuffix(v6.raw, test.payload) || len(v6.raw) != ipv6HeaderLength+8+len(test.payload) {
				t.Fatalf("ICMPv4 echo was not translated with its fields: %+v", v6.icmp)
			}
			v4 := translateToICMPv4(t, testTranslator(), v6.packet)
			if v4.icmp.TypeCode != layers.CreateICMPv4TypeCode(test.v4Type, 0) || v4.icmp.Id != test.id || v4.icmp.Seq != test.seq || !bytes.HasSuffix(v4.raw, test.payload) || len(v4.raw) != ipv4HeaderLength+8+len(test.payload) {
				t.Fatalf("ICMPv6 echo was not translated back with its fields: %+v", v4.icmp)
			}
		})
	}
}

// Local policy (RFC 792 and RFC 4443 Section 4.1 define Echo Code 0 only; RFC 7915 does not specify other codes):
// an Echo with a nonzero code is rejected in both directions.
func TestTranslateICMPEchoRejectsNonzeroCode(t *testing.T) {
	for _, messageType := range []uint8{echoRequest, echoReply} {
		t.Run(fmt.Sprintf("ICMPv4 type %d", messageType), func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: defaultTTL, Protocol: layers.IPProtocolICMPv4, SrcIP: ipv4Source, DstIP: ipv4Dest}
			icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(messageType, 1), Id: 1, Seq: 1}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp), layers.LayerTypeIPv4, gopacket.Default)
			result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
			requireRejected(t, result, err)
		})
	}
	for _, messageType := range []uint8{layers.ICMPv6TypeEchoRequest, layers.ICMPv6TypeEchoReply} {
		t.Run(fmt.Sprintf("ICMPv6 type %d", messageType), func(t *testing.T) {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: defaultTTL, SrcIP: ipv6Source, DstIP: ipv6Dest}
			icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(messageType, 1)}
			if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			input := gopacket.NewPacket(serializeTestPacket(t, ip, icmp, gopacket.Payload([]byte{0, 1, 0, 1})), layers.LayerTypeIPv6, gopacket.Default)
			result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
			requireRejected(t, result, err)
		})
	}
}

// RFC 7915 Figures 3 and 6 (MUST) with RFC 792 / RFC 4443: the Parameter Problem pointer is mapped octet by octet
// to the pointer of the other family, and pointers to a field that has no counterpart ("n/a") cause a silent drop.
// ICMPv4 carries the pointer in octet 4 of the message (codes 0 and 2 alike), ICMPv6 a 32-bit pointer. Every ICMPv4
// pointer 0-20 and every ICMPv6 pointer 0-41 is covered.
func TestTranslateICMPParameterProblemPointers(t *testing.T) {
	const drop = -1
	ipv4Pointers := map[uint8]int{0: 0, 1: 1, 2: 4, 3: 4, 8: 7, 9: 6, 12: 8, 13: 8, 14: 8, 15: 8, 16: 24, 17: 24, 18: 24, 19: 24}
	for _, code := range []uint8{0, 2} {
		for pointer := 0; pointer <= 20; pointer++ {
			want, mapped := ipv4Pointers[uint8(pointer)]
			if !mapped {
				want = drop // total length excepted, IPv4 octets 4-7, 10 and 11 and everything past the header are n/a
			}
			t.Run(fmt.Sprintf("IPv4 code %d pointer %d", code, pointer), func(t *testing.T) {
				input := ipv4ICMPPacketWithRest(t, layers.ICMPv4TypeParameterProblem, code, uint16(pointer)<<8, 0, ipv4TCPPacket(t, defaultTTL).Data())
				if want == drop {
					result, err := testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
					requireDropped(t, result, err)
					return
				}
				result := translateToICMPv6(t, testTranslator(), input)
				if result.icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0) {
					t.Fatalf("got %v, want Parameter Problem code 0", result.icmp.TypeCode)
				}
				if got := icmpPointerValue(t, result.icmp.Payload); got != uint32(want) {
					t.Fatalf("mapped pointer %d to %d, want %d", pointer, got, want)
				}
			})
		}
	}

	ipv6Pointer := func(pointer int) int {
		switch {
		case pointer == 0, pointer == 1:
			return pointer
		case pointer == 4, pointer == 5:
			return 2
		case pointer == 6:
			return 9
		case pointer == 7:
			return 8
		case pointer >= 8 && pointer <= 23:
			return 12
		case pointer >= 24 && pointer <= 39:
			return 16
		}
		return drop
	}
	for pointer := 0; pointer <= 41; pointer++ {
		want := ipv6Pointer(pointer)
		t.Run(fmt.Sprintf("IPv6 pointer %d", pointer), func(t *testing.T) {
			input := ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypeParameterProblem, 0, icmpPointer(uint32(pointer)), ipv6TCPPacket(t, defaultTTL).Data())
			if want == drop {
				result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
				requireDropped(t, result, err)
				return
			}
			result := translateToICMPv4(t, testTranslator(), input)
			if result.icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeParameterProblem, 0) {
				t.Fatalf("got %v, want Parameter Problem code 0", result.icmp.TypeCode)
			}
			if got := int(result.icmp.Id >> 8); got != want {
				t.Fatalf("mapped pointer %d to %d in ICMPv4 octet 4, want %d", pointer, got, want)
			}
		})
	}
	t.Run("IPv6 pointer past the packet", func(t *testing.T) {
		input := ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypeParameterProblem, 0, icmpPointer(1000), ipv6TCPPacket(t, defaultTTL).Data())
		result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
		requireDropped(t, result, err)
	})
}

// RFC 7915 Sections 4.2 and 5.2 (MUST): Destination Unreachable code 2 becomes Parameter Problem code 1 pointing
// at the IPv6 Next Header (6), and Parameter Problem code 1 becomes Destination Unreachable code 2 (Protocol).
func TestTranslateProtocolUnreachableAndUnrecognizedNextHeader(t *testing.T) {
	v6 := translateToICMPv6(t, testTranslator(), ipv4ICMPPacket(t, layers.ICMPv4TypeDestinationUnreachable, 2, ipv4TCPPacket(t, defaultTTL).Data()))
	if v6.icmp.TypeCode != layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 1) || icmpPointerValue(t, v6.icmp.Payload) != 6 {
		t.Fatalf("unexpected translation of Protocol Unreachable: %v pointer %d", v6.icmp.TypeCode, icmpPointerValue(t, v6.icmp.Payload))
	}
	v4 := translateToICMPv4(t, testTranslator(), ipv6ICMPPacketWithRestHeader(t, layers.ICMPv6TypeParameterProblem, 1, icmpPointer(40), ipv6TCPPacket(t, defaultTTL).Data()))
	if v4.icmp.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 2) {
		t.Fatalf("unexpected translation of Unrecognized Next Header: %v", v4.icmp.TypeCode)
	}
}
