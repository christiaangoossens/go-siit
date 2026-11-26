# RFC deviations

Things the RFCs recommend (SHOULD) or, in a few cases, require (MUST), which this library does not do, and what it does instead.

## ICMP errors for dropped packets

RFC 7915 Section 4.4: "the translator SHOULD be able to send back an ICMPv4 error message to the original sender of the packet"

Likewise RFC 7915 Section 5.4.

This optional error is not sent. It is a general Destination Unreachable (Type 3, Code 13, Communication Administratively Prohibited) for any packet the translator drops.

The specific ICMP errors are sent: Time Exceeded for an expired packet, Source Route Failed for an unexpired IPv4 source route, and Parameter Problem for an IPv6 Routing header with segments left. ICMP errors from other routers are translated as usual.

A caller that wants the general error can send it itself: the returned error says why the packet was dropped.

## Configuring or rate-limiting ICMP errors

RFC 7915 Section 4.4: "The translator SHOULD allow an administrator to configure whether the ICMPv4 error messages are sent, rate-limited, or not sent."

The ICMP errors the translator sends cannot be turned off or rate-limited.

## Hairpinning

RFC 7757 Section 4.2: "An SIIT implementation SHOULD include a feature that ensures that hairpinned IPv6 traffic is supported."

An IPv4 source that matches an EAM entry is always translated through that entry.

## Fragmenting packets that are too large

RFC 7915 Section 4.1: "the packet SHOULD be fragmented"

The translator never fragments. An IPv4 packet without the Don't Fragment bit that does not fit the IPv6 MTU is rejected with `ErrPacketOversized`, like a packet with the bit set.

## Fragmentation Needed

The translator does not send ICMPv4 "Fragmentation Needed" for a packet with the Don't Fragment bit set that is too large (RFC 7915 Section 4.1). It rejects the packet with `ErrPacketOversized`. Limit the IPv4 interface MTU to the IPv6 MTU minus 20, so the kernel sends this error instead.

## Ignoring the Type of Service

RFC 7915 Section 4.1: "An implementation of a translator SHOULD support an administratively configurable option to ignore the IPv4 TOS"

Likewise RFC 7915 Section 5.1.

The IPv4 TOS and the IPv6 Traffic Class are always copied.

## UDP without a checksum

RFC 7915 Section 4.5: "the translator SHOULD provide a configuration function"

This cannot be configured. An IPv4 UDP datagram without a checksum gets one. The first fragment of a fragmented datagram is rejected with `ErrZeroUDPChecksum` instead; its message names the addresses and ports, so the caller can log it.

## Illegal source addresses

RFC 7915 Section 4.1: "the translator SHOULD silently discard the packet (as discussed in Section 5.3.7 of [RFC1812])"

Only addresses that Go's `netip.Addr.IsGlobalUnicast` rejects are dropped. So with your own prefix (a Network-Specific Prefix, anything other than `64:ff9b::/96`), source addresses in `0.0.0.0/8` (network 0, apart from `0.0.0.0`) and `240.0.0.0/4` (Class E) are translated. With `64:ff9b::/96` (the Well-Known Prefix), the RFC 6052 Section 3.1 rule drops them.

## ICMP errors from or about illegal addresses

RFC 7915 Section 4.1: "Note when translating ICMPv4 Error Messages into ICMPv6, the "illegal" source address will be translated for the purpose of trouble shooting."

An ICMPv4 error is dropped when its source, or an address in the packet it quotes, is one the translator drops (see above). So traceroute hops through routers with such addresses are lost. With `64:ff9b::/96`, RFC 6052 Section 3.1 requires this drop for non-global addresses anyway.

## 6to4 relay anycast with the Well-Known Prefix

RFC 6052 Section 3.1: "The Well-Known Prefix MUST NOT be used to represent non-global IPv4 addresses, such as those defined in [RFC1918] or listed in Section 3 of [RFC5735]."

RFC 7526 Section 4: "This document formally deprecates the anycast 6to4 transition mechanism defined in [RFC3068] and the associated anycast IPv4 address 192.88.99.1."

RFC 5735 Section 3 lists 192.88.99.0/24, but the library translates it with `64:ff9b::/96`, because the block is no longer in use.

## RFC 7757 examples with the Well-Known Prefix

RFC 6052 Section 3.1: "they MUST drop these packets"

Some examples in RFC 7757 Appendix B use documentation addresses (192.0.2.0/24) with `64:ff9b::/96`. The translator drops those, as RFC 6052 requires.

## Packet Too Big below the IPv6 minimum

RFC 7915 Section 5.2: "The MTU field MUST be adjusted for the difference between the IPv4 and IPv6 header sizes"

An MTU below 1280 in an ICMPv6 Packet Too Big is first raised to 1280, so the ICMPv4 error reports 1260. IPv6 links never have a smaller MTU.

## Protocol numbers that belong to the other IP version

RFC 7915 Section 4.5: "translators MUST forward all transport protocols"

An IPv4 packet with protocol 0, 43, 44, 60 (IPv6 extension headers) or 58 (ICMPv6), and an IPv6 packet with Next Header 1 (ICMPv4), are rejected with `ErrUnsupportedProtocol`. The receiver would parse such a payload as something it is not.

## Packets with a wrong checksum

This is a local choice, not a deviation from an RFC requirement. A packet with a wrong IPv4 header checksum or transport checksum is rejected with `ErrInvalidPacket`, not forwarded with the checksum still wrong.

## ICMP extensions that do not fit

RFC 7915 Section 4.2: "the ICMPv4 extension SHOULD be simply truncated"

The quoted packet is shortened first. If the extension alone still does not fit, it is left out instead of truncated.
