package siit

import "errors"

// Every rejected packet returns an error that wraps exactly one of these, so errors.Is tells why it was rejected.
var (
	ErrInvalidPacket       = errors.New("Invalid packet")
	ErrInvalidICMP         = errors.New("Invalid ICMP packet")
	ErrUnsupportedProtocol = errors.New("Unsupported protocol")
	ErrTimeExceeded        = errors.New("TTL or Hop Limit expired")
	ErrSourceRouteFailed   = errors.New("Unexpired IPv4 source route")
	ErrUnsupportedSrcIP    = errors.New("Unsupported source IP address")
	ErrUnsupportedDestIP   = errors.New("Unsupported destination IP address")
	ErrPacketOversized     = errors.New("Packet is too large to be translated without possible fragmentation")
	ErrInvalidMTU          = errors.New("MTU is below the IPv6 minimum")
	ErrZeroUDPChecksum     = errors.New("UDP checksum is zero")
)

// TranslationError is returned for a rejected packet that the translator answers with an ICMP error.
type TranslationError struct {
	// Why the packet was rejected, one of the Err values.
	Err error

	// ICMP error for the sender of the rejected packet. Reply.Version tells which side it must be sent out on.
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
