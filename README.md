# go-siit

A Go library for stateless IP/ICMP translation (SIIT) between IPv4 and IPv6, as defined in [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html). It also implements:

- [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052.html): IPv6 Addressing of IPv4/IPv6 Translators
- [RFC 7757](https://www.rfc-editor.org/rfc/rfc7757.html): Explicit Address Mappings for Stateless IP/ICMP Translation

The library translates one packet per call. Reading and writing packets (tun devices, raw sockets, AF_XDP) is up to the caller. Callers that use raw bytes need only the standard library; callers that use [gopacket](https://github.com/google/gopacket) can pass their decoded layers.

The API reference, with runnable examples, is on [pkg.go.dev](https://pkg.go.dev/github.com/christiaangoossens/go-siit).

## Requirements for the caller

1. Pass packets that start at the IP header. Slice off a link header first, for example `frame[14:]` for Ethernet.
2. Keep packets of the same flow in order. The translator never queues or reorders packets (RFC 7915 Sections 4 and 5: "The translator SHOULD make sure that the packets belonging to the same flow leave the translator in the same order in which they arrived.").
3. Set the MTU of your IPv4 interface to 1260. The translator never splits packets (fragmentation): a packet that is too large is rejected with `ErrPacketOversized`. With this MTU, the kernel tells the sender to send smaller packets instead (ICMP Fragmentation Needed).
4. Set `Config.MTU` only when the IPv6 side supports packets larger than 1280 bytes, and set the IPv4 interface MTU to that value minus 20. An MTU below 1280 is rejected with `ErrInvalidMTU`.
5. Write a reply (see below) to the interface you read the packet from.

Why 1260: the IPv6 header is 20 bytes larger than the IPv4 header, and IPv6 guarantees 1280 bytes. An IPv4 packet that is already a fragment also needs an 8-byte IPv6 Fragment header, so it can be at most 1252 bytes.

The translator handles unicast traffic that is routed across it, not link-local protocols such as neighbor discovery.

## Usage

### Creating a translator

```go
translator, err := siit.NewTranslator(siit.Config{
	NAT64Prefix:       netip.MustParsePrefix("2001:db8:64::/96"), // RFC 6052
	IPv4RouterAddress: netip.MustParseAddr("192.0.2.1"),         // source of the ICMP errors the translator generates
	EAMTable:          nil,                                      // RFC 7757, may be empty
	MTU:               0,                                        // IPv6 path MTU, 0 means 1280
})
```

- **NAT64 prefix:** the IPv6 prefix that IPv4 addresses are put into (embedded in). With `64:ff9b::/96`, the IPv4 address 1.2.3.4 becomes `64:ff9b::102:304`. Most NAT64 networks use `64:ff9b::/96` (the Well-Known Prefix); others use their own prefix (a Network-Specific Prefix).
- **Router address:** an IPv4 address that stands for the translator itself. It is the sender of the error messages the translator creates.
- **EAM table:** fixed rules (Explicit Address Mappings) such as "IPv4 192.0.2.1 is IPv6 2001:db8::1". They take precedence over the prefix.

#### A private router address with 64:ff9b::/96

The RFCs do not allow private (non-global) IPv4 addresses inside the prefix `64:ff9b::/96` (RFC 6052 Section 3.1). So with that prefix, `NewTranslator` rejects a private router address such as 192.168.x.x or 192.0.0.x. Add an EAM entry that maps the router address to a public IPv6 address of this machine.

A CLAT, which gives one host IPv4 access on an IPv6-only network, typically needs this:

```go
router, _ := siit.ParseEAMEntry("192.0.0.254", publicIPv6.String()) // the CLAT's own IPv6 address
host, _ := siit.ParseEAMEntry("192.0.0.1", hostIPv6.String())

translator, err := siit.NewTranslator(siit.Config{
	NAT64Prefix:       netip.MustParsePrefix("64:ff9b::/96"),
	IPv4RouterAddress: netip.MustParseAddr("192.0.0.254"),
	EAMTable:          siit.EAMTable{router, host},
})
```

### Translating

```go
result, err := translator.TranslateIPv4(buffer[:n])
var translationErr *siit.TranslationError
switch {
case errors.As(err, &translationErr):
	writeToIPv4(translationErr.Reply) // an ICMP error back to the sender
case err != nil:
	log.Print(err) // rejected
case len(result) > 0:
	writeToIPv6(result) // translated
}
```

`TranslateIPv6` works the same in the other direction. A caller that already decoded the packet with gopacket passes the layer instead, so the packet is not decoded twice:

```go
ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
result, err := translator.TranslateIPv4Layer(ip)
```

| Outcome | Returned `Packet` | Error |
|---|---|---|
| Translated | the packet for the other side | `nil` |
| Dropped on purpose (for example IGMP) | empty | `nil` |
| Rejected | empty | wraps one of the `Err` values; `errors.Is` tells why |
| Rejected and answered | empty | a `*TranslationError` whose `Reply` you write to the interface you read the packet from |

`Packet` is a `[]byte`. `Src()`, `Dst()` and `Version()` read its header, and `Decode()` returns a lazily decoded gopacket view.

### Buffers and concurrency

- The input is never modified or kept, so the read buffer can be reused right away.
- Every returned `Packet` and `Reply` is a new slice that belongs to the caller. A view from `Decode()` shares its bytes.
- One `Translator` can be used from several goroutines.

## Limitations

- **No fragmentation.** A packet that does not fit the IPv6 MTU is rejected, so set the IPv4 MTU as described above.
- **No general ICMP error for dropped packets.** The specific ICMP errors, such as Time Exceeded, are sent. The optional "administratively prohibited" error for any other dropped packet is not. The returned error tells you why a packet was dropped, so you can send it yourself.
- **No rate limit** on the ICMP errors the translator sends.
- **No hairpinning.** Two IPv6 hosts that both have EAM entries cannot reach each other through the translator by their IPv4 addresses.

[docs/rfc-deviations.md](docs/rfc-deviations.md) lists every RFC recommendation that the library does not follow, with the RFC text.

## Migrating from v0.2

| v0.2 | v0.3 |
|---|---|
| `NewTranslator(nat64Net, router, eamTable)`, `NewTranslatorWithMTU(…, mtu)` | `NewTranslator(siit.Config{…})` with `netip` types |
| `RawEAMTable{{IPv4Prefix: "…", IPv6Prefix: "…"}}` | `EAMTable` of `EAMEntry`; `ParseEAMEntry("…", "…")` parses the text form |
| `Translator.MTU` | `Config.MTU` |
| `TranslateIPv4(packet gopacket.Packet, TranslationOverrides{})` | `TranslateIPv4(packet []byte)` or `TranslateIPv4Layer(*layers.IPv4)` |
| `TranslatedPacket{Packet, SrcIP, DstIP}` | `Packet` with `Src()`, `Dst()` and `Version()` |
| `TranslationError.Packet` | `TranslationError.Reply` |
| `ErrUnsupportedDestIP` | `ErrUnsupportedDstIP` |

Behaviour that changed:

- A generated ICMP error only arrives in `TranslationError.Reply`. Source Route Failed used to be returned as the translated packet with a `nil` error; it is now `ErrSourceRouteFailed` with a reply.
- Time Exceeded goes back in the family of the expired packet: an ICMPv4 error for an IPv4 packet, an ICMPv6 error for an IPv6 packet.
- Rejected packets no longer return addresses. Errors are lowercase, and new sentinels are `ErrSourceRouteFailed`, `ErrZeroUDPChecksum` and `ErrInvalidConfig`.
- The router address must be a unicast address, and a non-global one needs an EAM entry with the Well-Known Prefix (see above).

A tun loop changes like this:

```go
// v0.2
packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.Default)
result, err := translator.TranslateIPv4(packet, siit.TranslationOverrides{})
send(result.Packet, result.DstIP)

// v0.3
result, err := translator.TranslateIPv4(buffer[:n])
send(result, result.Dst())
```

## AI-declaration

The project is written with AI-assisted programming. Subagents are used to check all references and do code review first, then manual review is also performed before committing.
