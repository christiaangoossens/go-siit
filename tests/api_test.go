package siit_test

import (
	"errors"
	"net/netip"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket/layers"
)

var sentinels = []error{
	siit.ErrInvalidPacket, siit.ErrInvalidICMP, siit.ErrUnsupportedProtocol, siit.ErrTimeExceeded,
	siit.ErrSourceRouteFailed, siit.ErrUnsupportedSrcIP, siit.ErrUnsupportedDestIP, siit.ErrPacketOversized,
	siit.ErrInvalidMTU, siit.ErrZeroUDPChecksum,
}

// A rejected packet wraps exactly one sentinel, so a caller can pick the ICMP error it would send itself. A reply
// only ever arrives in TranslationError.Reply, for the side its Version names.
func TestRejectionsWrapOneSentinel(t *testing.T) {
	tests := []struct {
		name         string
		translate    func(t *testing.T) (translation, error)
		want         error
		replyVersion int
	}{
		{"IPv4 TTL expired", func(t *testing.T) (translation, error) {
			return translateIPv4(t, testTranslator(), ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, 1))
		}, siit.ErrTimeExceeded, 6},
		{"IPv6 Hop Limit expired", func(t *testing.T) (translation, error) {
			return translateIPv6(t, testTranslator(), ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, 1))
		}, siit.ErrTimeExceeded, 4},
		{"unexpired source route", func(t *testing.T) (translation, error) {
			return translateIPv4(t, testTranslator(), ipv4TCPPacketWithOptions(t, sourceRoute(131, 4), ipv4NOP))
		}, siit.ErrSourceRouteFailed, 4},
		{"unmappable IPv6 source", func(t *testing.T) (translation, error) {
			return translateIPv6(t, testTranslator(), ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Unmappable, ipv6Dest))
		}, siit.ErrUnsupportedSrcIP, 0},
		{"unmappable IPv6 destination", func(t *testing.T) (translation, error) {
			return translateIPv6(t, testTranslator(), ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, ipv6Unmappable))
		}, siit.ErrUnsupportedDestIP, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(t)
			if !errors.Is(err, test.want) || result.packet != nil {
				t.Fatalf("got err=%v, packet length %d, want %v", err, len(result.packet), test.want)
			}

			matches := 0
			for _, sentinel := range sentinels {
				if errors.Is(err, sentinel) {
					matches++
				}
			}
			if matches != 1 {
				t.Fatalf("error %q wraps %d sentinels", err, matches)
			}

			if version := siit.Packet(result.reply).Version(); version != test.replyVersion {
				t.Fatalf("reply version %d, want %d", version, test.replyVersion)
			}
		})
	}
}

func TestPacketReadsItsHeader(t *testing.T) {
	result := mustTranslate(t, func() (translation, error) {
		return translateIPv4(t, testTranslator(), ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL))
	})
	packet := siit.Packet(result)
	source, destination := netip.AddrFrom16([16]byte(ipv4TranslatedSource)), netip.AddrFrom16([16]byte(ipv4TranslatedDest))
	if packet.Version() != 6 || packet.Src() != source || packet.Dst() != destination {
		t.Fatalf("got version %d, %s -> %s", packet.Version(), packet.Src(), packet.Dst())
	}
	if decoded := packet.Decode(); decoded.Layer(layers.LayerTypeIPv6) == nil || decoded.Layer(layers.LayerTypeTCP) == nil {
		t.Fatalf("Decode did not return the IPv6 TCP packet: %v", decoded.ErrorLayer())
	}

	truncated := packet[:ipv6HeaderLength-1]
	if truncated.Version() != 6 || truncated.Src().IsValid() || truncated.Dst().IsValid() {
		t.Fatalf("truncated header returned %s -> %s", truncated.Src(), truncated.Dst())
	}

	var empty siit.Packet
	if empty.Version() != 0 || empty.Src().IsValid() || empty.Dst().IsValid() || empty.Decode() != nil {
		t.Fatal("empty packet does not report itself as empty")
	}
}

// A reply goes back towards the sender, so it has the family of the input, not of the translation.
func TestReplyDecodesInItsOwnFamily(t *testing.T) {
	result, _ := translateIPv4(t, testTranslator(), ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, 1))
	reply := siit.Packet(result.reply)
	source := netip.AddrFrom16([16]byte(ipv4TranslatedSource))
	if reply.Version() != 6 || reply.Dst() != source || reply.Decode().Layer(layers.LayerTypeICMPv6) == nil {
		t.Fatalf("Time Exceeded reply is not an ICMPv6 message to %s", source)
	}
}
