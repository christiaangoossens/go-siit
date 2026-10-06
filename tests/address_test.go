package siit_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RFC 6052 Section 3.1: the Well-Known Prefix must not represent non-global IPv4 addresses, and translators
// MUST drop packets in which an address is composed of the Well-Known Prefix and a non-global IPv4 address.
func TestTranslateWellKnownPrefixDropsNonGlobalIPv4(t *testing.T) {
	wellKnown := func(address string) net.IP {
		mapped := net.ParseIP("64:ff9b::").To16()
		copy(mapped[12:], net.ParseIP(address).To4())
		return mapped
	}
	for _, address := range []string{"10.0.0.1", "172.16.5.5", "192.168.1.1", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		ipv4 := net.ParseIP(address)
		tests := []struct {
			name      string
			translate func() (siit.TranslatedPacket, error)
		}{
			{"IPv4 source", func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4Dest), siit.TranslationOverrides{})
			}},
			{"IPv4 destination", func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv4(ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, ipv4), siit.TranslationOverrides{})
			}},
			{"IPv6 source", func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, wellKnown(address), ipv6Dest), siit.TranslationOverrides{})
			}},
			{"IPv6 destination", func() (siit.TranslatedPacket, error) {
				return testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, wellKnown(address)), siit.TranslationOverrides{})
			}},
		}
		for _, test := range tests {
			t.Run(address+" "+test.name, func(t *testing.T) {
				if result, _ := test.translate(); result.Packet != nil {
					t.Fatalf("packet with a non-global address in the Well-Known Prefix was translated")
				}
			})
		}
	}
}

// RFC 6052 Section 3.1 restricts only the Well-Known Prefix: a Network-Specific Prefix may carry any IPv4 address.
func TestTranslateNetworkSpecificPrefixMapsNonGlobalIPv4(t *testing.T) {
	translator := translatorWithPrefix(t, "2001:db8:122:344::/96", nil)
	input := ipv4TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"))
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(input, siit.TranslationOverrides{})
	})
	ip := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip.SrcIP.Equal(netIP("2001:db8:122:344::a00:1")) || !ip.DstIP.Equal(netIP("2001:db8:122:344::c0a8:101")) {
		t.Fatalf("non-global IPv4 addresses were not mapped into the Network-Specific Prefix: %s -> %s", ip.SrcIP, ip.DstIP)
	}
}

// RFC 7915 Sections 5.1 and 6, RFC 6791 Section 3: only ICMPv6 errors from native IPv6 routers use the router
// address. An ordinary packet whose source has no stateless mapping cannot be translated, because replies to the
// router address could not be mapped back.
func TestTranslateIPv6UnmappableSourceIsNotTranslated(t *testing.T) {
	result, err := testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Unmappable, ipv6Dest), siit.TranslationOverrides{})
	if result.Packet != nil {
		t.Fatalf("packet from an unmappable source was translated: err=%v", err)
	}
}

// RFC 6052 Section 2.2: suffix bits of an IPv4-embedded IPv6 address are ignored on receipt, and the u octet
// (bits 64-71) is skipped, for every prefix length other than 96.
func TestRFC6052IgnoresNonZeroSuffixBits(t *testing.T) {
	for _, test := range []struct{ name, prefix, base string }{
		{name: "32", prefix: "2001:db8::/32", base: "2001:db8:c000:221::"},
		{name: "40", prefix: "2001:db8:100::/40", base: "2001:db8:1c0:2:21::"},
		{name: "48", prefix: "2001:db8:122::/48", base: "2001:db8:122:c000:2:2100::"},
		{name: "56", prefix: "2001:db8:122:300::/56", base: "2001:db8:122:3c0:0:221::"},
		{name: "64", prefix: "2001:db8:122:344::/64", base: "2001:db8:122:344:c0:2:2100::"},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := netIP(test.base).To16()
			address[15] = 0x7f // last octet is always part of the suffix for these prefix lengths
			input := ipv6TCPPacketWithAddresses(t, defaultTTL, address, address)
			result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translatorWithPrefix(t, test.prefix, nil).TranslateIPv6(input, siit.TranslationOverrides{})
			})
			ip := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			want := net.ParseIP("192.0.2.33")
			if !ip.SrcIP.Equal(want) || !ip.DstIP.Equal(want) {
				t.Fatalf("non-zero suffix changed the embedded address: %s -> %s, want %s", ip.SrcIP, ip.DstIP, want)
			}
		})
	}
}

// RFC 6052 Section 2.2: bits 64-71 "MUST be set to zero"; with a /96 Network-Specific Prefix the administrator
// must ensure this, so a prefix with those bits set is a configuration error.
func TestNewTranslatorRejectsNonZeroUOctetIn96Prefix(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8:122:344:ff00::/96")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := siit.NewTranslator(prefix, ipv4RouterAddress, nil); err == nil {
		t.Fatal("/96 prefix with a non-zero u octet was accepted")
	}
}

// RFC 7757 Sections 3.1 and 3.2: invalid EAM table entries are rejected when the translator is created.
func TestNewTranslatorRejectsInvalidEAMTables(t *testing.T) {
	_, prefix, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		table siit.RawEAMTable
	}{
		{"duplicate IPv4 prefix", siit.RawEAMTable{{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"}, {IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:2::/56"}}},
		{"duplicate IPv6 prefix", siit.RawEAMTable{{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"}, {IPv4Prefix: "198.51.100.0/24", IPv6Prefix: "2001:db8:1::/56"}}},
		{"IPv4 suffix longer than IPv6 suffix", siit.RawEAMTable{{IPv4Prefix: "10.0.0.0/8", IPv6Prefix: "2001:db8::/120"}}},
		{"IPv6 prefix in IPv4 column", siit.RawEAMTable{{IPv4Prefix: "2001:db8::1", IPv6Prefix: "2001:db8::2"}}},
		{"IPv4 prefix in IPv6 column", siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "192.0.2.2"}}},
		{"IPv4-mapped IPv6 prefix", siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "::ffff:192.0.2.1"}}},
		{"IPv4 prefix length too long", siit.RawEAMTable{{IPv4Prefix: "192.0.2.1/33", IPv6Prefix: "2001:db8::1"}}},
		{"IPv6 prefix length too long", siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "2001:db8::1/129"}}},
		{"unparsable IPv4 prefix", siit.RawEAMTable{{IPv4Prefix: "not-an-address", IPv6Prefix: "2001:db8::1"}}},
		{"empty entry", siit.RawEAMTable{{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := siit.NewTranslator(prefix, ipv4RouterAddress, test.table); err == nil {
				t.Fatal("invalid EAM table was accepted")
			}
		})
	}

	t.Run("equal suffix lengths are valid", func(t *testing.T) {
		table := siit.RawEAMTable{{IPv4Prefix: "10.0.0.0/24", IPv6Prefix: "2001:db8::/120"}}
		if _, err := siit.NewTranslator(prefix, ipv4RouterAddress, table); err != nil {
			t.Fatalf("EAM with identical suffix lengths was rejected: %v", err)
		}
	})
}

// RFC 7757 Figure 1: the example EAM table and the translations that follow from the algorithm in Section 3.3.
func TestEAMTranslatesRFC7757ExampleTable(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "192.0.2.1", IPv6Prefix: "2001:db8:aaaa::"},
		{IPv4Prefix: "192.0.2.2/32", IPv6Prefix: "2001:db8:bbbb::b/128"},
		{IPv4Prefix: "192.0.2.16/28", IPv6Prefix: "2001:db8:cccc::/124"},
		{IPv4Prefix: "192.0.2.128/26", IPv6Prefix: "2001:db8:dddd::/64"},
		{IPv4Prefix: "192.0.2.192/29", IPv6Prefix: "2001:db8:eeee:8::/62"},
		{IPv4Prefix: "192.0.2.224/31", IPv6Prefix: "64:ff9b::/127"},
	})
	for _, test := range []struct{ ipv4, ipv6 string }{
		{"192.0.2.1", "2001:db8:aaaa::"},
		{"192.0.2.2", "2001:db8:bbbb::b"},
		{"192.0.2.20", "2001:db8:cccc::4"},
		{"192.0.2.129", "2001:db8:dddd:0:400::"},
		{"192.0.2.195", "2001:db8:eeee:9:8000::"},
		{"192.0.2.225", "64:ff9b::1"},
	} {
		t.Run(test.ipv4, func(t *testing.T) {
			ipv4, ipv6 := net.ParseIP(test.ipv4), netIP(test.ipv6)
			translated6 := gopacket.NewPacket(mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4), siit.TranslationOverrides{})
			}), layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !translated6.SrcIP.Equal(ipv6) || !translated6.DstIP.Equal(ipv6) {
				t.Fatalf("%s translated to %s -> %s, want %s", ipv4, translated6.SrcIP, translated6.DstIP, ipv6)
			}
			translated4 := gopacket.NewPacket(mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6, ipv6), siit.TranslationOverrides{})
			}), layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !translated4.SrcIP.Equal(ipv4) || !translated4.DstIP.Equal(ipv4) {
				t.Fatalf("%s translated to %s -> %s, want %s", ipv6, translated4.SrcIP, translated4.DstIP, ipv4)
			}
		})
	}
}

func TestEAMPrefixesMayOmitLengths(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "192.0.2.1", IPv6Prefix: "2001:db8::1"},
	})

	input := ipv4TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1"))
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(input, siit.TranslationOverrides{})
	})
	ip := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip.SrcIP.Equal(net.ParseIP("2001:db8::1")) || !ip.DstIP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("omitted EAM prefix lengths were not defaulted: %s -> %s", ip.SrcIP, ip.DstIP)
	}
}

func TestEAMSupportsRFC6052PrefixLengths(t *testing.T) {
	tests := []struct {
		name       string
		ipv4Prefix string
		ipv6Prefix string
		ipv4       string
		ipv6       string
	}{
		{name: "32", ipv4Prefix: "192.0.2.0/0", ipv6Prefix: "2001:db8::/32", ipv4: "192.0.2.33", ipv6: "2001:db8:c000:221::"},
		{name: "40", ipv4Prefix: "10.0.0.0/8", ipv6Prefix: "2001:db8:100::/40", ipv4: "10.1.2.3", ipv6: "2001:db8:101:203::"},
		{name: "48", ipv4Prefix: "10.20.0.0/16", ipv6Prefix: "2001:db8:122::/48", ipv4: "10.20.30.40", ipv6: "2001:db8:122:1e28::"},
		{name: "56", ipv4Prefix: "10.20.30.0/24", ipv6Prefix: "2001:db8:1234:5600::/56", ipv4: "10.20.30.40", ipv6: "2001:db8:1234:5628::"},
		{name: "64", ipv4Prefix: "10.20.30.40/32", ipv6Prefix: "2001:db8:1234:5678::/64", ipv4: "10.20.30.40", ipv6: "2001:db8:1234:5678::"},
		{name: "96", ipv4Prefix: "10.20.30.40/32", ipv6Prefix: "2001:db8:1234:5678:9abc:def0::/96", ipv4: "10.20.30.40", ipv6: "2001:db8:1234:5678:9abc:def0::"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			translator := testTranslatorWithEAM(siit.RawEAMTable{{
				IPv4Prefix: test.ipv4Prefix,
				IPv6Prefix: test.ipv6Prefix,
			}})
			ipv4 := net.ParseIP(test.ipv4)
			ipv6 := net.ParseIP(test.ipv6)

			ipv4Input := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4)
			ipv4Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(ipv4Input, siit.TranslationOverrides{})
			})
			translatedIPv6 := gopacket.NewPacket(ipv4Result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !translatedIPv6.SrcIP.Equal(ipv6) || !translatedIPv6.DstIP.Equal(ipv6) {
				t.Fatalf("IPv4-to-IPv6 EAM mapping was incorrect: %s -> %s, want %s", ipv4, translatedIPv6.SrcIP, ipv6)
			}

			ipv6Input := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6, ipv6)
			ipv6Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(ipv6Input, siit.TranslationOverrides{})
			})
			translatedIPv4 := gopacket.NewPacket(ipv6Result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !translatedIPv4.SrcIP.Equal(ipv4) || !translatedIPv4.DstIP.Equal(ipv4) {
				t.Fatalf("IPv6-to-IPv4 EAM mapping was incorrect: %s -> %s, want %s", ipv6, translatedIPv4.SrcIP, ipv4)
			}
		})
	}
}

func TestEAMTableSupportsMixedPrefixLengths(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"},
		{IPv4Prefix: "198.51.100.129/32", IPv6Prefix: "2001:db8:2::/64"},
	})
	tests := []struct {
		ipv4 string
		ipv6 string
	}{
		{ipv4: "192.0.2.33", ipv6: "2001:db8:1:21::"},
		{ipv4: "198.51.100.129", ipv6: "2001:db8:2::"},
	}

	for _, test := range tests {
		t.Run(test.ipv4, func(t *testing.T) {
			ipv4 := net.ParseIP(test.ipv4)
			ipv6 := net.ParseIP(test.ipv6)

			ipv4Input := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4)
			ipv4Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(ipv4Input, siit.TranslationOverrides{})
			})
			translatedIPv6 := gopacket.NewPacket(ipv4Result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !translatedIPv6.SrcIP.Equal(ipv6) || !translatedIPv6.DstIP.Equal(ipv6) {
				t.Fatalf("mixed EAM prefix mapping was incorrect: %s -> %s, want %s", ipv4, translatedIPv6.SrcIP, ipv6)
			}

			ipv6Input := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6, ipv6)
			ipv6Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(ipv6Input, siit.TranslationOverrides{})
			})
			translatedIPv4 := gopacket.NewPacket(ipv6Result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !translatedIPv4.SrcIP.Equal(ipv4) || !translatedIPv4.DstIP.Equal(ipv4) {
				t.Fatalf("mixed EAM reverse mapping was incorrect: %s -> %s, want %s", ipv6, translatedIPv4.SrcIP, ipv4)
			}
		})
	}
}

func TestEAMLookupUsesMoreSpecificPrefixInsertedLater(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"},
		{IPv4Prefix: "192.0.2.128/25", IPv6Prefix: "2001:db8:2::/64"},
	})
	tests := []struct {
		name string
		ipv4 string
		ipv6 string
	}{
		{name: "less specific match", ipv4: "192.0.2.33", ipv6: "2001:db8:1:21::"},
		{name: "more specific match", ipv4: "192.0.2.200", ipv6: "2001:db8:2:0:9000::"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipv4 := net.ParseIP(test.ipv4)
			ipv6 := net.ParseIP(test.ipv6)

			ipv4Input := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4)
			ipv4Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(ipv4Input, siit.TranslationOverrides{})
			})
			translatedIPv6 := gopacket.NewPacket(ipv4Result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !translatedIPv6.SrcIP.Equal(ipv6) || !translatedIPv6.DstIP.Equal(ipv6) {
				t.Fatalf("unexpected longest-prefix EAM match: %s -> %s, want %s", ipv4, translatedIPv6.SrcIP, ipv6)
			}

			ipv6Input := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6, ipv6)
			ipv6Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(ipv6Input, siit.TranslationOverrides{})
			})
			translatedIPv4 := gopacket.NewPacket(ipv6Result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !translatedIPv4.SrcIP.Equal(ipv4) || !translatedIPv4.DstIP.Equal(ipv4) {
				t.Fatalf("unexpected reverse EAM match: %s -> %s, want %s", ipv6, translatedIPv4.SrcIP, ipv4)
			}
		})
	}
}

func TestEAMIPv6ToIPv4DiscardsExcessSuffixBits(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "192.0.2.128/26", IPv6Prefix: "2001:db8:dddd::/64"},
	})
	ipv6 := net.ParseIP("2001:db8:dddd:0:6000:beef::")
	input := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6, ipv6)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv6(input, siit.TranslationOverrides{})
	})
	ip := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	want := net.ParseIP("192.0.2.152")
	if !ip.SrcIP.Equal(want) || !ip.DstIP.Equal(want) {
		t.Fatalf("IPv6 suffix was not truncated according to RFC 7757: %s -> %s, want %s", ipv6, ip.SrcIP, want)
	}
}

// RFC 7757: explicit address mappings are supplied through the EAM table.
func TestTranslateUsesEAMMappings(t *testing.T) {
	translator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
		{IPv4Prefix: "2.2.2.2/32", IPv6Prefix: "2001:db8::20/128"},
	})

	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return translator.TranslateIPv4(ipv4TCPPacket(t, defaultTTL), siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip.SrcIP.Equal(net.ParseIP("2001:db8::10")) || !ip.DstIP.Equal(net.ParseIP("2001:db8::20")) {
		t.Fatalf("EAM mapping was ignored: %s -> %s", ip.SrcIP, ip.DstIP)
	}

	result = mustTranslate(t, func() (siit.TranslatedPacket, error) {
		input := ipv6TCPPacketWithAddresses(t, defaultTTL, net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20"))
		return translator.TranslateIPv6(input, siit.TranslationOverrides{})
	})
	packet = gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip4.SrcIP.Equal(ipv4Source) || !ip4.DstIP.Equal(ipv4Dest) {
		t.Fatalf("reverse EAM mapping was ignored: %s -> %s", ip4.SrcIP, ip4.DstIP)
	}

	oneSidedTranslator := testTranslatorWithEAM(siit.RawEAMTable{
		{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"},
	})
	result = mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return oneSidedTranslator.TranslateIPv4(ipv4TCPPacket(t, defaultTTL), siit.TranslationOverrides{})
	})
	packet = gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip = packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip.SrcIP.Equal(net.ParseIP("2001:db8::10")) || !ip.DstIP.Equal(ipv4TranslatedDest) {
		t.Fatalf("one-sided EAM mapping was applied incorrectly: %s -> %s", ip.SrcIP, ip.DstIP)
	}
}

// RFC 6052 Section 2.2: the NAT64 prefix uses one of the six permitted lengths.
func TestNewTranslatorValidatesConfiguration(t *testing.T) {
	_, validPrefix, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatal(err)
	}
	_, unsupportedPrefix, err := net.ParseCIDR("64:ff9b::/80")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		prefix     *net.IPNet
		routerAddr net.IP
	}{
		{name: "nil prefix", prefix: nil, routerAddr: ipv4RouterAddress},
		{name: "unsupported prefix length", prefix: unsupportedPrefix, routerAddr: ipv4RouterAddress},
		{name: "nil router", prefix: validPrefix, routerAddr: nil},
		{name: "IPv6 router", prefix: validPrefix, routerAddr: net.ParseIP("2001:db8::1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := siit.NewTranslator(test.prefix, test.routerAddr, nil); err == nil {
				t.Fatal("invalid translator configuration was accepted")
			}
		})
	}
}

func TestTranslateRFC6052NAT64PrefixLengths(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		ipv4       string
		expectedV6 string
	}{
		{name: "32", prefix: "2001:db8::/32", ipv4: "192.0.2.33", expectedV6: "2001:db8:c000:221::"},
		{name: "40", prefix: "2001:db8:100::/40", ipv4: "192.0.2.33", expectedV6: "2001:db8:1c0:2:21::"},
		{name: "48", prefix: "2001:db8:122::/48", ipv4: "192.0.2.33", expectedV6: "2001:db8:122:c000:2:2100::"},
		{name: "56", prefix: "2001:db8:122:300::/56", ipv4: "192.0.2.33", expectedV6: "2001:db8:122:3c0:0:221::"},
		{name: "64", prefix: "2001:db8:122:344::/64", ipv4: "192.0.2.33", expectedV6: "2001:db8:122:344:c0:2:2100::"},
		{name: "96", prefix: "2001:db8:122:344::/96", ipv4: "192.0.2.33", expectedV6: "2001:db8:122:344::192.0.2.33"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, nat64Net, err := net.ParseCIDR(test.prefix)
			if err != nil {
				t.Fatal(err)
			}
			translator, err := siit.NewTranslator(nat64Net, ipv4RouterAddress, nil)
			if err != nil {
				t.Fatal(err)
			}

			ipv4 := net.ParseIP(test.ipv4)
			expectedV6 := net.ParseIP(test.expectedV6)
			ipv4Input := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4)
			ipv4Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv4(ipv4Input, siit.TranslationOverrides{})
			})
			translatedV6 := gopacket.NewPacket(ipv4Result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !translatedV6.SrcIP.Equal(expectedV6) || !translatedV6.DstIP.Equal(expectedV6) {
				t.Fatalf("RFC 6052 mapping was incorrect: %s -> %s, want %s", ipv4, translatedV6.SrcIP, expectedV6)
			}

			ipv6Input := ipv6TCPPacketWithAddresses(t, defaultTTL, expectedV6, expectedV6)
			ipv6Result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
				return translator.TranslateIPv6(ipv6Input, siit.TranslationOverrides{})
			})
			translatedV4 := gopacket.NewPacket(ipv6Result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !translatedV4.SrcIP.Equal(ipv4) || !translatedV4.DstIP.Equal(ipv4) {
				t.Fatalf("RFC 6052 reverse mapping was incorrect: %s -> %s, want %s", expectedV6, translatedV4.SrcIP, ipv4)
			}
		})
	}
}

// RFC 6052 Section 2 and RFC 7915 Section 6: a global IPv4 address is embedded in the /96 prefix.
func TestRFC6052MappingGlobalAddress(t *testing.T) {
	ipv4 := net.ParseIP("8.8.8.8").To4()
	input := ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4)
	result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
		return testTranslator().TranslateIPv4(input, siit.TranslationOverrides{})
	})
	packet := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	want := net.ParseIP("64:ff9b::808:808")
	if !ip.SrcIP.Equal(want) || !ip.DstIP.Equal(want) {
		t.Fatalf("mapped %s to %s -> %s, want %s", ipv4, ip.SrcIP, ip.DstIP, want)
	}
}

// RFC 7915 Sections 5.1, 5.6 and 6: an IPv6 destination with no IPv4 mapping is not in the IPv4 domain.
func TestTranslateIPv6RejectsUnmappableDestination(t *testing.T) {
	input := ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, ipv6Unmappable)
	result, err := testTranslator().TranslateIPv6(input, siit.TranslationOverrides{})
	if !errors.Is(err, siit.ErrInvalidPacket) || !strings.Contains(err.Error(), "not mappable") || result.Packet != nil {
		t.Fatalf("IPv6 destination outside the NAT64 prefix was not rejected for being unmappable: err=%v", err)
	}
}
