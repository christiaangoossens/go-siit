package siit_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// A rejected packet wraps one sentinel (checked by the test seam for every rejection), so a caller can pick the ICMP
// error it would send itself. A reply only ever arrives in TranslationError.Reply, in the family of the rejected
// packet, because it goes back to the sender.
func TestRejectionsReturnTheirReasonAndReply(t *testing.T) {
	tests := []struct {
		name         string
		translate    func(t *testing.T) (translation, error)
		want         error
		replyVersion int
	}{
		{"IPv4 TTL expired", func(t *testing.T) (translation, error) {
			return translateIPv4(t, testTranslator(), ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, 1))
		}, siit.ErrTimeExceeded, 4},
		{"IPv6 Hop Limit expired", func(t *testing.T) (translation, error) {
			return translateIPv6(t, testTranslator(), ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, 1))
		}, siit.ErrTimeExceeded, 6},
		{"unexpired source route", func(t *testing.T) (translation, error) {
			return translateIPv4(t, testTranslator(), ipv4TCPPacketWithOptions(t, sourceRoute(131, 4), ipv4NOP))
		}, siit.ErrSourceRouteFailed, 4},
		{"unmappable IPv6 source", func(t *testing.T) (translation, error) {
			return translateIPv6(t, testTranslator(), ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Unmappable, ipv6Dest))
		}, siit.ErrUnsupportedSrcIP, 0},
		{"unmappable IPv6 destination", func(t *testing.T) (translation, error) {
			return translateIPv6(t, testTranslator(), ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, ipv6Unmappable))
		}, siit.ErrUnsupportedDstIP, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.translate(t)
			if !errors.Is(err, test.want) || result.packet != nil {
				t.Fatalf("got err=%v, packet length %d, want %v", err, len(result.packet), test.want)
			}
			if version := siit.Packet(result.reply).Version(); version != test.replyVersion {
				t.Fatalf("reply version %d, want %d", version, test.replyVersion)
			}
		})
	}
}

// Input that holds less than its length fields declare is rejected, because the translated length fields would not
// match the translated packet.
func TestTranslateRejectsTruncatedInput(t *testing.T) {
	ipv4 := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()
	ipv6 := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, defaultTTL).Data()

	// gopacket treats a Total Length of 0 as "the length of the data" (TCP segmentation offload).
	zeroLength := slices.Clone(ipv4)
	binary.BigEndian.PutUint16(zeroLength[2:4], 0)
	clear(zeroLength[ipv4ChecksumOffset : ipv4ChecksumOffset+2])
	binary.BigEndian.PutUint16(zeroLength[ipv4ChecksumOffset:], checksum(zeroLength[:ipv4HeaderLength]))

	for name, data := range map[string][]byte{"IPv4": ipv4[:len(ipv4)-1], "IPv4 Total Length 0": zeroLength} {
		t.Run(name, func(t *testing.T) {
			result, err := translateIPv4(t, testTranslator(), gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default))
			if !errors.Is(err, siit.ErrInvalidPacket) || result.packet != nil {
				t.Fatalf("got err=%v, packet length %d, want ErrInvalidPacket", err, len(result.packet))
			}
		})
	}
	t.Run("IPv6", func(t *testing.T) {
		result, err := translateIPv6(t, testTranslator(), gopacket.NewPacket(ipv6[:len(ipv6)-1], layers.LayerTypeIPv6, gopacket.Default))
		if !errors.Is(err, siit.ErrInvalidPacket) || result.packet != nil {
			t.Fatalf("got err=%v, packet length %d, want ErrInvalidPacket", err, len(result.packet))
		}
	})
}

// Bytes after the declared length, like Ethernet padding, are not part of the packet.
func TestTranslateIgnoresTrailingBytes(t *testing.T) {
	padding := []byte{0, 0, 0, 0}
	ipv4 := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()
	ipv6 := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, defaultTTL).Data()

	padded := mustTranslate(t, func() (translation, error) {
		return translateIPv4(t, testTranslator(), gopacket.NewPacket(append(slices.Clone(ipv4), padding...), layers.LayerTypeIPv4, gopacket.Default))
	})
	plain := mustTranslate(t, func() (translation, error) {
		return translateIPv4(t, testTranslator(), gopacket.NewPacket(ipv4, layers.LayerTypeIPv4, gopacket.Default))
	})
	if !bytes.Equal(padded, plain) {
		t.Fatal("padding after the IPv4 Total Length changed the translation")
	}

	padded = mustTranslate(t, func() (translation, error) {
		return translateIPv6(t, testTranslator(), gopacket.NewPacket(append(slices.Clone(ipv6), padding...), layers.LayerTypeIPv6, gopacket.Default))
	})
	plain = mustTranslate(t, func() (translation, error) {
		return translateIPv6(t, testTranslator(), gopacket.NewPacket(ipv6, layers.LayerTypeIPv6, gopacket.Default))
	})
	if !bytes.Equal(withoutIdentification(padded), withoutIdentification(plain)) {
		t.Fatal("padding after the IPv6 Payload Length changed the translation")
	}
}

// A layer that did not come from decoding is an invalid packet, whatever its address fields say.
func TestTranslateLayerRejectsEmptyLayers(t *testing.T) {
	translator := testTranslator()
	for name, translate := range map[string]func() (siit.Packet, error){
		"nil IPv4":        func() (siit.Packet, error) { return translator.TranslateIPv4Layer(nil) },
		"zero IPv4":       func() (siit.Packet, error) { return translator.TranslateIPv4Layer(&layers.IPv4{}) },
		"nil IPv6":        func() (siit.Packet, error) { return translator.TranslateIPv6Layer(nil) },
		"zero IPv6":       func() (siit.Packet, error) { return translator.TranslateIPv6Layer(&layers.IPv6{}) },
		"empty IPv4 data": func() (siit.Packet, error) { return translator.TranslateIPv4(nil) },
		"empty IPv6 data": func() (siit.Packet, error) { return translator.TranslateIPv6(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := translate(); !errors.Is(err, siit.ErrInvalidPacket) || result != nil {
				t.Fatalf("got err=%v, packet length %d, want ErrInvalidPacket", err, len(result))
			}
		})
	}
}

// Local configuration contract: the router address is the source of generated ICMP errors, so it must be a unicast
// address the translator can map back.
func TestNewTranslatorRejectsUnusableRouterAddresses(t *testing.T) {
	for _, router := range []string{"0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "::ffff:9.9.9.9", "192.0.0.1"} {
		t.Run(router, func(t *testing.T) {
			config := testConfig("64:ff9b::/96", nil)
			config.IPv4RouterAddress = netip.MustParseAddr(router)
			if _, err := siit.NewTranslator(config); !errors.Is(err, siit.ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
	t.Run("non-global with a Network-Specific Prefix", func(t *testing.T) {
		config := testConfig("2001:db8:64::/96", nil)
		config.IPv4RouterAddress = netip.MustParseAddr("192.0.0.1")
		if _, err := siit.NewTranslator(config); err != nil {
			t.Fatalf("router address was rejected: %v", err)
		}
	})
}

// Changing the configuration after NewTranslator does not change the translator.
func TestNewTranslatorCopiesTheEAMTable(t *testing.T) {
	config := testConfig("64:ff9b::/96", eamTable)
	translator := newTestTranslator(config)
	config.EAMTable[0] = siit.EAMEntry{IPv4Prefix: netip.MustParsePrefix("1.1.1.1/32"), IPv6Prefix: netip.MustParsePrefix("2001:db8::99/128")}

	result := mustTranslate(t, func() (translation, error) {
		return translateIPv4(t, translator, ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL))
	})
	if source := siit.Packet(result).Src(); source != netip.MustParseAddr("2001:db8::10") {
		t.Fatalf("source %s, want the mapping from creation time 2001:db8::10", source)
	}
}

// One translator may be used from several goroutines; run with -race.
func TestTranslatorIsSafeForConcurrentUse(t *testing.T) {
	translator := testTranslator()
	ipv4 := ipv4Segment(t, segmentTCP, ipv4Source, ipv4Dest, defaultTTL).Data()
	ipv6 := ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, defaultTTL).Data()

	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 100 {
				fromIPv4, err4 := translator.TranslateIPv4(ipv4)
				fromIPv6, err6 := translator.TranslateIPv6(ipv6)
				if err4 != nil || err6 != nil || len(fromIPv4) == 0 || len(fromIPv6) == 0 {
					t.Errorf("concurrent translation failed: %v, %v", err4, err6)
					return
				}
			}
		})
	}
	group.Wait()
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

// A CLAT with the Well-Known Prefix and a non-global router address (as go-clat runs) maps the router address with an
// EAM entry, which its ICMPv6 errors then come from.
func TestRouterAddressMappedByEAM(t *testing.T) {
	config := testConfig("64:ff9b::/96", rawEAMTable{{IPv4Prefix: "192.0.0.254", IPv6Prefix: "2001:db8::254"}})
	config.IPv4RouterAddress = netip.MustParseAddr("192.0.0.254")
	translator, err := siit.NewTranslator(config)
	if err != nil {
		t.Fatalf("router address with an EAM entry was rejected: %v", err)
	}

	result, _ := translateIPv6(t, translator, ipv6Segment(t, segmentTCP, ipv6Source, ipv6Dest, 1))
	if reply := siit.Packet(result.reply); reply.Src() != netip.MustParseAddr("2001:db8::254") {
		t.Fatalf("Time Exceeded comes from %s, want the EAM address 2001:db8::254", reply.Src())
	}
}
