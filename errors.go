package siit

import "errors"

// A rejected packet returns an error that wraps exactly one of these, so errors.Is tells why it was rejected.
var (
	ErrInvalidPacket       = errors.New("invalid packet")
	ErrInvalidICMP         = errors.New("invalid ICMP packet")
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	ErrTimeExceeded        = errors.New("TTL or Hop Limit expired")
	ErrSourceRouteFailed   = errors.New("unexpired IPv4 source route")
	ErrUnsupportedSrcIP    = errors.New("unsupported source IP address")
	ErrUnsupportedDstIP    = errors.New("unsupported destination IP address")
	ErrPacketOversized     = errors.New("packet is too large to be translated without possible fragmentation")
	ErrZeroUDPChecksum     = errors.New("UDP checksum is zero")
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

	// ICMP error for the sender of the rejected packet, to send back out the side the packet came from.
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
