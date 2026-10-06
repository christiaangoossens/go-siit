package siit_test

import (
	"fmt"
	"net"
	"testing"

	siit "github.com/christiaangoossens/go-siit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	bothDirections = iota
	ipv4ToIPv6Only
	ipv6ToIPv4Only
)

// requireAddressMapping sends packets whose source and destination are the given address through the translator
// and checks that both the source and the destination come out as the expected address of the other family.
func requireAddressMapping(t *testing.T, translator *siit.Translator, ipv4, ipv6 net.IP, direction int) {
	t.Helper()
	if direction != ipv6ToIPv4Only {
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return translator.TranslateIPv4(ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4), siit.TranslationOverrides{})
		})
		ip := gopacket.NewPacket(result, layers.LayerTypeIPv6, gopacket.Default).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !ip.SrcIP.Equal(ipv6) || !ip.DstIP.Equal(ipv6) {
			t.Fatalf("IPv4 %s was translated to %s -> %s, want %s", ipv4, ip.SrcIP, ip.DstIP, ipv6)
		}
	}
	if direction != ipv4ToIPv6Only {
		result := mustTranslate(t, func() (siit.TranslatedPacket, error) {
			return translator.TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6, ipv6), siit.TranslationOverrides{})
		})
		ip := gopacket.NewPacket(result, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ip.SrcIP.Equal(ipv4) || !ip.DstIP.Equal(ipv4) {
			t.Fatalf("IPv6 %s was translated to %s -> %s, want %s", ipv6, ip.SrcIP, ip.DstIP, ipv4)
		}
	}
}

// embedIPv4 is an independent implementation of the address format of RFC 6052 Section 2.2: the IPv4 address is
// placed after the prefix, skipping the reserved bits 64-71 (the "u" octet), followed by a zero suffix.
func embedIPv4(prefix net.IP, length int, ipv4 net.IP) net.IP {
	address := make(net.IP, 16)
	copy(address, prefix.To16()[:length/8])
	position := length / 8
	for _, value := range ipv4.To4() {
		if position == 8 {
			position++ // skip bits 64 to 71
		}
		address[position] = value
		position++
	}
	return address
}

// RFC 6052 Sections 2.2 and 2.3 (MUST): an IPv4 address is embedded in, and extracted from, an IPv6 address
// according to the prefix length (32, 40, 48, 56, 64 or 96), with the "u" octet (bits 64-71) skipped and a zero
// suffix. The first address is the example of Section 2.4, Table 1; the others come from a reference implementation.
func TestRFC6052AddressFormat(t *testing.T) {
	tests := []struct {
		prefix  string
		example string // RFC 6052 Section 2.4 for 192.0.2.33
	}{
		{prefix: "2001:db8::/32", example: "2001:db8:c000:221::"},
		{prefix: "2001:db8:100::/40", example: "2001:db8:1c0:2:21::"},
		{prefix: "2001:db8:122::/48", example: "2001:db8:122:c000:2:2100::"},
		{prefix: "2001:db8:122:300::/56", example: "2001:db8:122:3c0:0:221::"},
		{prefix: "2001:db8:122:344::/64", example: "2001:db8:122:344:c0:2:2100::"},
		{prefix: "2001:db8:122:344::/96", example: "2001:db8:122:344::192.0.2.33"},
		{prefix: "64:ff9b::/96", example: "64:ff9b::192.0.2.33"},
	}
	for _, test := range tests {
		_, network, err := net.ParseCIDR(test.prefix)
		if err != nil {
			t.Fatal(err)
		}
		length, _ := network.Mask.Size()
		t.Run(test.prefix, func(t *testing.T) {
			translator := translatorWithPrefix(t, test.prefix, nil)
			example := net.ParseIP("192.0.2.33").To4()
			if want := net.ParseIP(test.example); !embedIPv4(network.IP, length, example).Equal(want) {
				t.Fatalf("the test's reference implementation gives %s, RFC 6052 gives %s", embedIPv4(network.IP, length, example), want)
			}
			addresses := []string{"8.8.8.8", "1.2.3.4", "203.0.114.255", "223.1.2.3"}
			if test.prefix != "64:ff9b::/96" {
				// Documentation addresses are not global, so only a Network-Specific Prefix may carry them.
				addresses = append(addresses, "192.0.2.33", "198.51.100.7")
			}
			for _, address := range addresses {
				ipv4 := net.ParseIP(address).To4()
				t.Run(address, func(t *testing.T) {
					requireAddressMapping(t, translator, ipv4, embedIPv4(network.IP, length, ipv4), bothDirections)
				})
			}
		})
	}
}

// RFC 6052 Section 3.1 (MUST for the Well-Known Prefix): the Well-Known Prefix is not used for non-global IPv4
// addresses, and a packet in which either address is a Well-Known Prefix address with a non-global IPv4 address is
// dropped. The matrix includes the neighbours of each range, which must still be translated. A Network-Specific
// Prefix has no such restriction (it still refuses addresses that can never be unicast hosts).
func TestTranslateWellKnownPrefixAddressRestrictions(t *testing.T) {
	tests := []struct {
		address string
		global  bool
	}{
		{"0.1.2.3", false}, {"10.0.0.1", false}, {"10.255.255.255", false}, {"11.0.0.1", true},
		{"100.63.255.255", true}, {"100.64.0.1", false}, {"100.127.255.255", false}, {"100.128.0.1", true},
		{"127.0.0.2", false}, {"169.253.255.255", true}, {"169.254.1.1", false}, {"169.255.0.1", true},
		{"172.15.255.255", true}, {"172.16.5.5", false}, {"172.31.255.255", false}, {"172.32.0.1", true},
		{"192.0.0.1", false}, {"192.0.1.1", true}, {"192.0.2.1", false}, {"192.0.3.1", true},
		{"192.167.255.255", true}, {"192.168.1.1", false}, {"192.169.0.1", true},
		{"198.17.255.255", true}, {"198.18.0.1", false}, {"198.19.255.255", false}, {"198.20.0.1", true},
		{"198.51.100.1", false}, {"203.0.113.1", false}, {"203.0.114.1", true},
		{"224.0.0.1", false}, {"240.0.0.1", false},
	}
	nsp := translatorWithPrefix(t, "2001:db8:122:344::/96", nil)
	// Even a Network-Specific Prefix refuses addresses that cannot be the address of a unicast host.
	neverUnicast := map[string]bool{"0.1.2.3": true, "127.0.0.2": true, "169.254.1.1": true, "224.0.0.1": true, "240.0.0.1": true}
	for _, test := range tests {
		ipv4 := net.ParseIP(test.address).To4()
		wellKnown := expectedMappedAddress(ipv4)
		t.Run(test.address, func(t *testing.T) {
			attempts := map[string]func() (siit.TranslatedPacket, error){
				"IPv4 source": func() (siit.TranslatedPacket, error) {
					return testTranslator().TranslateIPv4(ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4, ipv4Dest), siit.TranslationOverrides{})
				},
				"IPv4 destination": func() (siit.TranslatedPacket, error) {
					return testTranslator().TranslateIPv4(ipv4TCPPacketWithAddresses(t, defaultTTL, ipv4Source, ipv4), siit.TranslationOverrides{})
				},
				"IPv6 source": func() (siit.TranslatedPacket, error) {
					return testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, wellKnown, ipv6Dest), siit.TranslationOverrides{})
				},
				"IPv6 destination": func() (siit.TranslatedPacket, error) {
					return testTranslator().TranslateIPv6(ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, wellKnown), siit.TranslationOverrides{})
				},
			}
			for name, attempt := range attempts {
				result, err := attempt()
				if test.global && result.Packet == nil {
					t.Errorf("%s: global address was not translated: %v", name, err)
				}
				if !test.global && result.Packet != nil {
					t.Errorf("%s: non-global address in the Well-Known Prefix was translated", name)
				}
			}
			if !neverUnicast[test.address] {
				requireAddressMapping(t, nsp, ipv4, embedIPv4(net.ParseIP("2001:db8:122:344::"), 96, ipv4), bothDirections)
			}
		})
	}
}

// RFC 7915 Sections 5.1 and 6 with RFC 6791 Section 3 and RFC 6052 Section 3.1: only ICMPv6 errors from native IPv6
// routers use the router address. An ordinary packet from a source, or to a destination, that has no stateless
// mapping cannot be translated, because replies could not be mapped back.
func TestTranslateIPv6WithoutMappingIsRejected(t *testing.T) {
	for name, packet := range map[string]gopacket.Packet{
		"source":      ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Unmappable, ipv6Dest),
		"destination": ipv6TCPPacketWithAddresses(t, defaultTTL, ipv6Source, ipv6Unmappable),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := testTranslator().TranslateIPv6(packet, siit.TranslationOverrides{})
			requireRejected(t, result, err)
		})
	}
}

// RFC 6052 Section 2.2 (SHOULD): "embedded IPv6 addresses where [suffix] bits are not zero SHOULD ignore" them.
func TestRFC6052IgnoresNonZeroSuffixBits(t *testing.T) {
	for _, prefix := range []string{"2001:db8::/32", "2001:db8:100::/40", "2001:db8:122::/48", "2001:db8:122:300::/56", "2001:db8:122:344::/64"} {
		t.Run(prefix, func(t *testing.T) {
			_, network, _ := net.ParseCIDR(prefix)
			length, _ := network.Mask.Size()
			address := embedIPv4(network.IP, length, net.ParseIP("192.0.2.33").To4())
			address[15] = 0x7f // the last octet is always part of the suffix for these prefix lengths
			requireAddressMapping(t, translatorWithPrefix(t, prefix, nil), net.ParseIP("192.0.2.33").To4(), address, ipv6ToIPv4Only)
		})
	}
}

// RFC 6052 Sections 2.2 and 2.3 (MUST) and RFC 7757 Sections 3.1 and 3.2: the translator refuses configurations
// that violate the specifications: unsupported prefix lengths, a /96 prefix with the reserved "u" octet set, a
// missing or IPv6 router address, and EAM tables with conflicting or malformed entries.
func TestNewTranslatorRejectsInvalidConfiguration(t *testing.T) {
	parse := func(prefix string) *net.IPNet {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return network
	}
	wellKnown := parse("64:ff9b::/96")
	tests := []struct {
		name   string
		prefix *net.IPNet
		router net.IP
		table  siit.RawEAMTable
	}{
		{"nil prefix", nil, ipv4RouterAddress, nil},
		{"prefix length 80", parse("64:ff9b::/80"), ipv4RouterAddress, nil},
		{"prefix length 128", parse("64:ff9b::1/128"), ipv4RouterAddress, nil},
		{"/96 prefix with a non-zero u octet", parse("2001:db8:122:344:ff00::/96"), ipv4RouterAddress, nil},
		{"nil router", wellKnown, nil, nil},
		{"IPv6 router", wellKnown, net.ParseIP("2001:db8::1"), nil},
		{"duplicate IPv4 prefix", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"}, {IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:2::/56"}}},
		{"duplicate IPv6 prefix", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"}, {IPv4Prefix: "198.51.100.0/24", IPv6Prefix: "2001:db8:1::/56"}}},
		{"IPv4 suffix longer than IPv6 suffix", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "10.0.0.0/8", IPv6Prefix: "2001:db8::/120"}}},
		{"IPv6 prefix in IPv4 column", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "2001:db8::1", IPv6Prefix: "2001:db8::2"}}},
		{"IPv4 prefix in IPv6 column", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "192.0.2.2"}}},
		{"IPv4-mapped IPv6 prefix", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "::ffff:192.0.2.1"}}},
		{"IPv4 prefix length too long", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "192.0.2.1/33", IPv6Prefix: "2001:db8::1"}}},
		{"IPv6 prefix length too long", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "2001:db8::1/129"}}},
		{"unparsable IPv4 prefix", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{IPv4Prefix: "not-an-address", IPv6Prefix: "2001:db8::1"}}},
		{"empty entry", wellKnown, ipv4RouterAddress, siit.RawEAMTable{{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := siit.NewTranslator(test.prefix, test.router, test.table); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
	t.Run("equal suffix lengths are valid", func(t *testing.T) {
		table := siit.RawEAMTable{{IPv4Prefix: "10.0.0.0/24", IPv6Prefix: "2001:db8::/120"}}
		if _, err := siit.NewTranslator(wellKnown, ipv4RouterAddress, table); err != nil {
			t.Fatalf("EAM with identical suffix lengths was rejected: %v", err)
		}
	})
}

// RFC 7757 Sections 3.1-3.3 (MUST): the EAM table maps by longest-prefix match in either column, the host bits
// are carried over (and excess IPv6 suffix bits are discarded on the way to IPv4), prefixes without a length are
// single hosts, an address without an entry falls back to the RFC 6052 prefix, and every packet address is
// translated independently. The first table is Figure 1 of the RFC.
func TestEAMMappings(t *testing.T) {
	type mapping struct {
		ipv4, ipv6 string
		direction  int
	}
	tests := []struct {
		name     string
		table    siit.RawEAMTable
		mappings []mapping
	}{
		{
			name: "RFC 7757 Figure 1",
			table: siit.RawEAMTable{
				{IPv4Prefix: "192.0.2.1", IPv6Prefix: "2001:db8:aaaa::"},
				{IPv4Prefix: "192.0.2.2/32", IPv6Prefix: "2001:db8:bbbb::b/128"},
				{IPv4Prefix: "192.0.2.16/28", IPv6Prefix: "2001:db8:cccc::/124"},
				{IPv4Prefix: "192.0.2.128/26", IPv6Prefix: "2001:db8:dddd::/64"},
				{IPv4Prefix: "192.0.2.192/29", IPv6Prefix: "2001:db8:eeee:8::/62"},
				{IPv4Prefix: "192.0.2.224/31", IPv6Prefix: "64:ff9b::/127"},
			},
			mappings: []mapping{
				{"192.0.2.1", "2001:db8:aaaa::", bothDirections},
				{"192.0.2.2", "2001:db8:bbbb::b", bothDirections},
				{"192.0.2.20", "2001:db8:cccc::4", bothDirections},
				{"192.0.2.129", "2001:db8:dddd:0:400::", bothDirections},
				{"192.0.2.195", "2001:db8:eeee:9:8000::", bothDirections},
				{"192.0.2.225", "64:ff9b::1", bothDirections},
			},
		},
		{
			name:  "prefixes without a length are single hosts",
			table: siit.RawEAMTable{{IPv4Prefix: "192.0.2.1", IPv6Prefix: "2001:db8::1"}},
			mappings: []mapping{
				{"192.0.2.1", "2001:db8::1", bothDirections},
			},
		},
		{
			name: "mixed prefix lengths",
			table: siit.RawEAMTable{
				{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"},
				{IPv4Prefix: "198.51.100.129/32", IPv6Prefix: "2001:db8:2::/64"},
			},
			mappings: []mapping{
				{"192.0.2.33", "2001:db8:1:21::", bothDirections},
				{"198.51.100.129", "2001:db8:2::", bothDirections},
			},
		},
		{
			name: "more specific IPv4 prefix wins",
			table: siit.RawEAMTable{
				{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/56"},
				{IPv4Prefix: "192.0.2.128/25", IPv6Prefix: "2001:db8:2::/64"},
			},
			mappings: []mapping{
				{"192.0.2.33", "2001:db8:1:21::", bothDirections},
				{"192.0.2.200", "2001:db8:2:0:9000::", bothDirections},
			},
		},
		{
			name: "more specific IPv6 prefix wins",
			table: siit.RawEAMTable{
				{IPv4Prefix: "192.0.2.0/24", IPv6Prefix: "2001:db8:1::/64"},
				{IPv4Prefix: "198.51.100.0/24", IPv6Prefix: "2001:db8:1:0:8000::/72"},
			},
			mappings: []mapping{
				{"192.0.2.5", "2001:db8:1:0:500::", bothDirections},
				{"198.51.100.5", "2001:db8:1:0:8005::", bothDirections},
				// Inside the shorter IPv6 prefix but outside the longer one.
				{"192.0.2.127", "2001:db8:1:0:7fff::4d", ipv6ToIPv4Only},
			},
		},
		{
			name:  "IPv6 suffix bits beyond the IPv4 host part are discarded",
			table: siit.RawEAMTable{{IPv4Prefix: "192.0.2.128/26", IPv6Prefix: "2001:db8:dddd::/64"}},
			mappings: []mapping{
				{"192.0.2.152", "2001:db8:dddd:0:6000:beef::", ipv6ToIPv4Only},
			},
		},
		{
			name:  "addresses without an entry use the RFC 6052 prefix",
			table: siit.RawEAMTable{{IPv4Prefix: "1.1.1.1/32", IPv6Prefix: "2001:db8::10/128"}},
			mappings: []mapping{
				{"1.1.1.1", "2001:db8::10", bothDirections},
				{"2.2.2.2", "64:ff9b::202:202", bothDirections},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			translator := testTranslatorWithEAM(test.table)
			for _, mapping := range test.mappings {
				t.Run(fmt.Sprintf("%s %s", mapping.ipv4, mapping.ipv6), func(t *testing.T) {
					requireAddressMapping(t, translator, net.ParseIP(mapping.ipv4).To4(), net.ParseIP(mapping.ipv6), mapping.direction)
				})
			}
		})
	}
}

// RFC 7757 Section 3.2 (MUST): the IPv4 and IPv6 prefixes of an EAM entry may have any of the lengths of RFC 6052.
func TestEAMSupportsRFC6052PrefixLengths(t *testing.T) {
	for _, test := range []struct{ name, ipv4Prefix, ipv6Prefix, ipv4, ipv6 string }{
		{"32", "192.0.2.0/0", "2001:db8::/32", "192.0.2.33", "2001:db8:c000:221::"},
		{"40", "10.0.0.0/8", "2001:db8:100::/40", "10.1.2.3", "2001:db8:101:203::"},
		{"48", "10.20.0.0/16", "2001:db8:122::/48", "10.20.30.40", "2001:db8:122:1e28::"},
		{"56", "10.20.30.0/24", "2001:db8:1234:5600::/56", "10.20.30.40", "2001:db8:1234:5628::"},
		{"64", "10.20.30.40/32", "2001:db8:1234:5678::/64", "10.20.30.40", "2001:db8:1234:5678::"},
		{"96", "10.20.30.40/32", "2001:db8:1234:5678:9abc:def0::/96", "10.20.30.40", "2001:db8:1234:5678:9abc:def0::"},
	} {
		t.Run(test.name, func(t *testing.T) {
			translator := testTranslatorWithEAM(siit.RawEAMTable{{IPv4Prefix: test.ipv4Prefix, IPv6Prefix: test.ipv6Prefix}})
			requireAddressMapping(t, translator, net.ParseIP(test.ipv4).To4(), net.ParseIP(test.ipv6), bothDirections)
		})
	}
}
