# go-siit
golang library implementation of Stateless IP/ICMP Translation Algorithm (SIIT) as defined in [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html)

It also implements:

- [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052.html): IPv6 Addressing of IPv4/IPv6 Translators
- [RFC 7757](https://www.rfc-editor.org/rfc/rfc7757.html): Explicit Address Mappings for Stateless IP/ICMP Translation

## Assumptions

- The kernel handles routing, MTU enforcement, and packet fragmentation.
- `Translator` receives IPv4 packets or fragments no larger than 1260 bytes, including the IPv4 header.
- `Translator` does not perform MTU-driven fragmentation or generate MTU errors.
- We only support unicast packets.
- We only support internet routable packets (not LAN-internal, such as discovery protocols)

The 1260-byte bound is derived from IPv6's 1280-byte minimum link MTU: replacing the 20-byte IPv4 header with a 40-byte IPv6 header adds 20 bytes, so an unfragmented IPv4 packet of 1260 bytes or less becomes an IPv6 packet of 1280 bytes or less. Packets within this boundary should never need MTU-driven fragmentation in this library; the Linux kernel handles fragmentation outside that boundary.

## Usage

The library exposes an object called `Translator` which you can create using `NewTranslator(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable) (*Translator, error)`

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