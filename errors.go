package siit

import "errors"

// A rejected packet returns an error that wraps exactly one of these, so errors.Is tells why it was rejected.
var (
	// The packet is malformed: a bad header, length or checksum, or a Routing header with segments left.
	ErrInvalidPacket = errors.New("invalid packet")

	// The ICMP message is malformed, for example too short or with an invalid code. ICMP messages that have no
	// translation are dropped without an error.
	ErrInvalidICMP = errors.New("invalid ICMP packet")

	// The packet carries something the translator does not translate, such as a fragmented ICMP message.
	ErrUnsupportedProtocol = errors.New("unsupported protocol")

	// The TTL or Hop Limit ran out. Usually the error is a *TranslationError with a Time Exceeded reply to send. Some
	// packets must not be answered, such as ICMP errors; then the error is plain and there is nothing to send.
	ErrTimeExceeded = errors.New("TTL or Hop Limit expired")

	// The IPv4 packet asks to be routed along a fixed path (an unexpired source route option), which the translator
	// cannot follow. Usually the error is a
	// *TranslationError with a Source Route Failed reply to send. For an ICMP error there is nothing to send.
	ErrSourceRouteFailed = errors.New("unexpired IPv4 source route")

	// The source address is not unicast, cannot be mapped, or must not be mapped.
	ErrUnsupportedSrcIP = errors.New("unsupported source IP address")

	// The destination address is not unicast, cannot be mapped, or must not be mapped.
	ErrUnsupportedDstIP = errors.New("unsupported destination IP address")

	// The translated packet would be larger than the IPv6 MTU. The translator never splits packets (fragmentation).
	ErrPacketOversized = errors.New("packet too large for the IPv6 MTU")

	// A UDP checksum of zero that cannot be handled. The message names the addresses and ports, for the caller to
	// log.
	ErrZeroUDPChecksum = errors.New("UDP checksum is zero")
)

// NewTranslator returns an error wrapping ErrInvalidConfig for an invalid Config, and also ErrInvalidMTU when the MTU
// is the problem.
var (
	ErrInvalidConfig = errors.New("invalid translator configuration")
	ErrInvalidMTU    = errors.New("MTU is below the IPv6 minimum")
)

// TranslationError is returned for a rejected packet that the translator answers with an ICMP error.
type TranslationError struct {
	// Why the packet was rejected, one of the Err values.
	Err error

	// ICMP error for the sender of the rejected packet. Write it to the interface you read the packet from.
	Reply Packet
}

func (e *TranslationError) Error() string {
	return e.Err.Error()
}

func (e *TranslationError) Unwrap() error {
	return e.Err
}

// withReply attaches a generated ICMP error to err. When no reply could be generated, err is returned as is.
func withReply(err error, reply Packet) error {
	if len(reply) == 0 {
		return err
	}

	return &TranslationError{Err: err, Reply: reply}
}
