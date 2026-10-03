# go-siit
golang library implementation of Stateless IP/ICMP Translation Algorithm (SIIT) as defined in [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html)

## Assumptions

- The kernel handles routing, MTU enforcement, and packet fragmentation.
- `Translator` receives IPv4 packets or fragments no larger than 1260 bytes, including the IPv4 header.
- `Translator` does not perform MTU-driven fragmentation or generate MTU errors.
- We only support unicast packets.
- We only support internet routable packets (not LAN-internal, such as discovery protocols)

The 1260-byte bound is derived from IPv6's 1280-byte minimum link MTU: replacing the 20-byte IPv4 header with a 40-byte IPv6 header adds 20 bytes, so an unfragmented IPv4 packet of 1260 bytes or less becomes an IPv6 packet of 1280 bytes or less. Packets within this boundary should never need MTU-driven fragmentation in this library; the Linux kernel handles fragmentation outside that boundary.

## AI-declaration
Test suite is AI-assisted programming with manual review. The main library itself is manually written (with AI review/suggestions only).