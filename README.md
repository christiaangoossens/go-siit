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

The minimum link IPv6 MTU is 1280 bytes. For an unfragmented IPv4 packet, the maximum total IPv4 size is calculated as `MTU - 40 + 20`, so 1260 bytes is accepted. An already fragmented IPv4 packet additionally needs an 8-byte IPv6 Fragment header, so its maximum total IPv4 size is `MTU - 40 - 8 + 20`, or 1252 bytes (1232 bytes of IPv4 payload after the IPv4 header).

The MTU defaults to 1280. An administrator who knows the IPv6 side supports a larger MTU can use `NewTranslatorWithMTU` (or set `Translator.MTU`); the caller must then also configure its tun interface to that MTU. The translator never fragments: a packet that does not fit within the configured MTU is rejected with `ErrPacketOversized`, and an MTU below 1280 is rejected at creation with `ErrInvalidMTU`.

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

## Unsupported

This library currently does not support:

- Some RFC 7915 `SHOULD`-level ICMP error responses for discarded packets (Sections 4.4 and 5.4). Those packets are silently dropped instead. Mandatory ICMP translations and protocol-specific error responses remain implemented.
- ICMP error emission cannot currently be configured or rate-limited.
- Hairpinning of EAM-translated traffic (RFC 7757 Section 4, `SHOULD`): IPv4 sources are always translated through the EAM table when they match.
- Sending ICMPv4 "Fragmentation Needed" for oversized packets with the Don't Fragment bit set (RFC 7915 Section 4.1). Packets exceeding the maximum size are rejected with `ErrPacketOversized`; the caller must limit the IPv4 interface MTU to the IPv6 MTU minus 20 so the kernel reports this error instead.
- Ignoring the IPv4 TOS / IPv6 Traffic Class (RFC 7915 Sections 4.1 and 5.1, `SHOULD`): the field is always copied.

## AI-declaration

Test suite is AI programming with manual review. The main library itself is manually written (with AI review/assistance only).