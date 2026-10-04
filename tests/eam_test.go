package siit_test

import (
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
