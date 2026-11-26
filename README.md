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
- The caller keeps packets of the same flow in order. `Translator` translates one packet per call and never queues or reorders them (RFC 7915 Sections 4 and 5: "The translator SHOULD make sure that the packets belonging to the same flow leave the translator in the same order in which they arrived.").

The minimum link IPv6 MTU is 1280 bytes. For an unfragmented IPv4 packet, the maximum total IPv4 size is calculated as `MTU - 40 + 20`, so 1260 bytes is accepted. An already fragmented IPv4 packet additionally needs an 8-byte IPv6 Fragment header, so its maximum total IPv4 size is `MTU - 40 - 8 + 20`, or 1252 bytes (1232 bytes of IPv4 payload after the IPv4 header).

The MTU defaults to 1280. An administrator who knows the IPv6 side supports a larger MTU can use `NewTranslatorWithMTU` (or set `Translator.MTU`); the caller must then also configure its tun interface to that MTU. The translator never fragments: a packet that does not fit within the configured MTU is rejected with `ErrPacketOversized`, and an MTU below 1280 is rejected at creation with `ErrInvalidMTU`.

## Usage

The library exposes an object called `Translator` which you can create using `NewTranslator(nat64Net *net.IPNet, ipv4RouterAddress net.IP, eamTable RawEAMTable) (*Translator, error)`. Use `NewTranslatorWithMTU` when the path MTU is known at creation time.

You should supply a NAT64 net (for RFC 6052), an IPv4 router address (when ICMP packets cannot have their source translated) and an EAM table (which may be empty for pure RFC 6052).

Then, you can use the following functions on `Translator` to translate packets, starting at the IP header:

```
TranslateIPv4(packet []byte) (Packet, error)
TranslateIPv6(packet []byte) (Packet, error)

// For packets that are already decoded with gopacket:
TranslateIPv4Layer(ip *layers.IPv4) (Packet, error)
TranslateIPv6Layer(ip *layers.IPv6) (Packet, error)
```

`Packet` is the translated packet as bytes, with `Src()`, `Dst()` and `Version()` read from its header and `Decode()` for a lazy gopacket view. It is empty when the packet is dropped (`nil` error) or rejected (an error wrapping one of the `Err` values).

When the translator answers a rejected packet with an ICMP error, the error is a `*TranslationError` whose `Reply` must be sent back out on the side that `Reply.Version()` names:

```go
result, err := translator.TranslateIPv4(buffer[:n])
var translationErr *siit.TranslationError
if errors.As(err, &translationErr) {
	send(translationErr.Reply)
}
if len(result) > 0 {
	writeToIPv6(result)
}
```

## Unsupported

This library currently does not support:

- ICMP error responses for discarded packets (RFC 7915 Section 4.4: "the translator SHOULD be able to send back an ICMPv4 error message to the original sender of the packet", and likewise RFC 7915 Section 5.4). Those packets are dropped without one. Mandatory ICMP translations and protocol-specific error responses remain implemented.
- ICMP error emission cannot currently be configured or rate-limited.
- Hairpinning of EAM-translated traffic (RFC 7757 Section 4.2: "An SIIT implementation SHOULD include a feature that ensures that hairpinned IPv6 traffic is supported."). IPv4 sources are always translated through the EAM table when they match.
- Fragmenting IPv4 packets without the Don't Fragment bit that do not fit the IPv6 MTU (RFC 7915 Section 4.1: "the packet SHOULD be fragmented"). They are rejected with `ErrPacketOversized`, like packets with the bit set.
- Sending ICMPv4 "Fragmentation Needed" for oversized packets with the Don't Fragment bit set (RFC 7915 Section 4.1). Packets exceeding the maximum size are rejected with `ErrPacketOversized`; the caller must limit the IPv4 interface MTU to the IPv6 MTU minus 20 so the kernel reports this error instead.
- Ignoring the IPv4 TOS / IPv6 Traffic Class (RFC 7915 Section 4.1: "An implementation of a translator SHOULD support an administratively configurable option to ignore the IPv4 TOS", and likewise RFC 7915 Section 5.1). The field is always copied.
- Configuring how IPv4 UDP datagrams with a zero checksum are handled (RFC 7915 Section 4.5: "the translator SHOULD provide a configuration function"). An unfragmented datagram always gets a computed checksum. The first fragment of a fragmented one is always rejected with `ErrZeroUDPChecksum`, whose message names the addresses and ports for the caller to log.
- Discarding every illegal IPv4 source address (RFC 7915 Section 4.1: "the translator SHOULD silently discard the packet (as discussed in Section 5.3.7 of [RFC1812])"). Only addresses that are not global unicast according to Go's `net.IP.IsGlobalUnicast` are rejected. With a Network-Specific Prefix, network 0 (`0.0.0.0/8` apart from `0.0.0.0`) and Class E (`240.0.0.0/4`) addresses are therefore translated. With the Well-Known Prefix they are dropped by the RFC 6052 Section 3.1 rule.
- Truncating an ICMPv4 extension that does not fit in the ICMPv6 message (RFC 7915 Section 4.2: "the ICMPv4 extension SHOULD be simply truncated"). The quoted packet is truncated first; if the extension alone still does not fit, it is left out instead of truncated.

## AI-declaration

Test suite is AI programming with manual review. The main library itself is manually written (with AI review/assistance only).