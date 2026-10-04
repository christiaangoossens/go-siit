# go-siit
golang library implementation of Stateless IP/ICMP Translation Algorithm (SIIT) as defined in [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html)

It also implements:

- [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052.html): IPv6 Addressing of IPv4/IPv6 Translators
- [RFC 7757](https://www.rfc-editor.org/rfc/rfc7757.html): Explicit Address Mappings for Stateless IP/ICMP Translation

## Assumptions

- The kernel handles routing, MTU enforcement, and packet fragmentation.
- `Translator` receives does not receive oversized packets. Fragmentation is already preformed if necessary.
- `Translator` does not perform MTU-driven fragmentation.
- We only support unicast packets.
- We only support internet routable packets (not LAN-internal, such as discovery protocols).

The minimum link IPv6 MTU is 1280 bytes. For an unfragmented IPv4 packet, the maximum total IPv4 size is calculated as `MTU - 40 + 20`, so 1260 bytes is accepted by default. An already fragmented IPv4 packet additionally needs an 8-byte IPv6 Fragment header, so its maximum total IPv4 size is `MTU - 40 - 8 + 20`, or 1252 bytes by default (1232 bytes of IPv4 payload after the IPv4 header). An administrator who knows a larger path MTU is supported can set `Translator.MTU`; for example, 1500 permits 1480-byte unfragmented packets and 1472-byte fragmented packets.

## Usage

The library exposes an object called `Translator` which you can create using `NewTranslator(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable) (*Translator, error)`. Use `NewTranslatorWithMTU` when the path MTU is known at creation time.

You should supply a NAT64 net (for RFC 6052), an IPv4 router address (when ICMP packets cannot have their source translated) and an EAM table (which may be empty for pure RFC 6052).

Then, you can use the following functions on `Translator` to translate packets:

```
TranslateIPv4(packet gopacket.Packet, overrides TranslationOverrides) (TranslatedPacket, error)

TranslateIPv6(packet gopacket.Packet, overrides TranslationOverrides) (TranslatedPacket, error)
```

You should not need to specify any translation overrides (they are just used for quoted packets that have different handling).

The `TranslatedPacket` has the following type:

```
type TranslatedPacket struct {
	Packet []byte
	SrcIP  net.IP
	DstIP  net.IP
}
```

You can use the src & dest IPs for logging. They are also returned on error (whenever possible).

## AI-declaration
Test suite is AI-assisted programming with manual review. The main library itself is manually written (with AI review/suggestions only).