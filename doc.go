// Package siit translates packets between IPv4 and IPv6 without keeping state (SIIT, RFC 7915), with the addressing
// of RFC 6052 and the explicit address mappings of RFC 7757.
//
// # Creating a translator
//
// NewTranslator takes a Config with:
//   - the NAT64 prefix, the IPv6 prefix that IPv4 addresses are put into (embedded in),
//   - the router address, an IPv4 address that stands for the translator itself and sends its error messages,
//   - optionally an EAM table of fixed rules (Explicit Address Mappings) such as 'IPv4 192.0.2.1 is IPv6 2001:db8::1',
//   - optionally the IPv6 MTU.
//
// A Translator cannot be changed after it is created, so one translator can serve several goroutines.
//
// The RFCs do not allow private (non-global) IPv4 addresses inside the prefix 64:ff9b::/96 (the Well-Known Prefix,
// RFC 6052 Section 3.1). So with that prefix, a private router address such as 192.0.0.254 (as a CLAT uses) needs an
// EAM entry that maps it to a public IPv6 address of this machine.
//
// # Translating
//
// TranslateIPv4 and TranslateIPv6 take a raw packet that starts at the IP header and need only the standard library.
// A caller that reads link-layer frames slices the link header off first, for example frame[14:] for Ethernet; bytes
// after the IP length, like Ethernet padding, are ignored. A caller that already decoded the packet with gopacket
// passes the layer to TranslateIPv4Layer or TranslateIPv6Layer instead, so it is not decoded twice.
//
// The result is one of:
//   - A translated packet and a nil error: write the packet to the interface for the other IP version.
//   - An empty packet and a nil error: the packet is dropped on purpose, for example IGMP.
//   - An empty packet and an error that wraps one of the Err values: the packet is rejected. errors.Is tells why.
//   - An empty packet and a *TranslationError with a Reply: the packet is rejected and answered with an ICMP error.
//     Write the reply to the interface you read the packet from.
//
// # Buffers
//
// The input is never modified or kept, so a caller can reuse its read buffer right away. Every Packet is a new slice
// that belongs to the caller. Packet.Decode returns a gopacket view that shares the bytes of the packet.
package siit
