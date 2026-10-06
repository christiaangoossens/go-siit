package siit

/**
 * RFC 4884 (Extended ICMP to Support Multi-Part Messages)
 */

const icmpExtensionMinimumDatagram = 128

// splitICMPExtension splits the data of an ICMP error on its Length attribute (counted in words of unit octets).
func splitICMPExtension(data []byte, words, unit int) ([]byte, []byte) {
	length := words * unit
	if length < icmpExtensionMinimumDatagram || length >= len(data) {
		return data, nil
	}

	return data[:length], data[length:]
}

// joinICMPQuote truncates the quote to fit and appends the extension behind the quote, zero padded to at least 128
// octets and whole words. It returns the Length attribute in words, 0 if the extension no longer fits.
func joinICMPQuote(quote, extension []byte, maximum, unit int) ([]byte, int) {
	available := (maximum - len(extension)) / unit * unit
	if len(extension) == 0 || available < icmpExtensionMinimumDatagram {
		return quote[:min(len(quote), maximum)], 0
	}

	quote = quote[:min(len(quote), available)]
	padded := max(icmpExtensionMinimumDatagram, (len(quote)+unit-1)/unit*unit)
	data := make([]byte, padded, padded+len(extension))
	copy(data, quote)
	return append(data, extension...), padded / unit
}
