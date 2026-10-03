# go-siit
golang library implementation of Stateless IP/ICMP Translation Algorithm (SIIT) as defined in [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html)

## Assumptions

- The Linux kernel handles routing, MTU enforcement, and packet fragmentation.
- `Translator` receives IPv4 packets or fragments no larger than 1260 bytes, including the IPv4 header.
- `Translator` does not perform MTU-driven fragmentation or generate MTU errors.
- We only support TCP, UDP and ICMP translation.
- We only support unicast packets.
- We only support internet routable packets (not LAN-internal)

The 1260-byte bound allows an unfragmented IPv4 packet to become a 1280-byte
IPv6 packet after replacing its 20-byte IPv4 header with a 40-byte IPv6 header.


## Unsupported
- Multicast or broadcast packets, unicast only
- Any non-internet ICMP that only exists within a network is silently dropped, such as router advertisements, MLD, router or neighbor solicitation/advertisement, ARP, and NDP.
- IPv4 and IPv6 fragments, including translator-side fragmentation.