// Package siit_test checks the translator against RFC 7915 (SIIT), RFC 6052 (address format) and RFC 7757 (EAM).
// Where those RFCs defer to another one, that RFC is named: RFC 4443 (ICMPv6), RFC 4884 (ICMP extensions), RFC 1191
// (plateaus), RFC 1812 (router requirements), RFC 6791 (router source address) and RFC 8200 (IPv6). The cases were
// cross-checked with the Python tests of TAYGA (https://github.com/apalrd/tayga/tree/main/test), leaving out what
// TAYGA does that this library does not (stateful features, fragmentation, ICMP rate limiting).
//
// Conventions:
//   - The doc comment of every Test function names the requirement it covers. Level words follow the RFC: MUST,
//     SHOULD. "Local" means a rule of this library (see the README) that the RFCs do not prescribe.
//   - Almost every test function is a matrix (t.Run per row) named after the case it checks.
//   - Shared fixtures live in fixtures_test.go. ICMP errors are always built in the direction a real error travels:
//     the outer source is the quoted packet's destination and the outer destination is the quoted packet's source.
//
// Where the requirements are tested:
//   - IP header translation: basic_translation_test.go, ip_header_test.go
//   - Transport protocols and checksums: basic_translation_test.go, checksum_test.go, robustness_test.go
//   - Addresses (RFC 6052, EAM): address_test.go
//   - ICMP and ICMP errors: icmp_error_test.go, icmp_translation_test.go, icmp_extension_test.go
//   - Fragments: fragments_test.go
//
// Deliberately not tested, because the README lists it as unsupported: SHOULD-level behaviour the library does not
// implement, namely ICMP errors for other discarded packets (RFC 7915 Sections 4.4 and 5.4), hairpinning (RFC 7757
// Section 4), fragmentation of packets without DF and Fragmentation Needed for packets with DF (Section 4.1),
// ignoring TOS / Traffic Class, configurable zero-checksum UDP, discarding every illegal source (network 0 and
// Class E are translated with a Network-Specific Prefix) and truncating (instead of leaving out) an ICMP extension.
// Likewise untested are Time Exceeded messages with a code above 1 (the RFC says "the Code is unchanged" but ICMPv6
// defines none) and the jumbogram case (Section 5.1, out of scope).
package siit_test
