package siit

import (
	"hash/maphash"
	"math/rand/v2"
	"net"
	"sync/atomic"
)

const identificationCounters = 8192

// identificationGenerator is the Fragment Identification generator of RFC 7915 Section 5.1, using the hash-based
// algorithm of RFC 7739 Section 5.3: "Identification = F(Src IP, Dst IP, secret1) + counter[G(Src IP, Dst Pref,
// secret2)]"
//
// F and G are taken from one keyed hash of the IPv4 source and destination. G uses the whole destination address, not
// a prefix. Packets to one destination count up, so their values do not repeat soon, while the values of different
// destinations are unrelated. It is safe for concurrent use.
type identificationGenerator struct {
	seed     maphash.Seed
	counters [identificationCounters]atomic.Uint32
}

func newIdentificationGenerator() *identificationGenerator {
	generator := &identificationGenerator{seed: maphash.MakeSeed()}
	for i := range generator.counters {
		generator.counters[i].Store(rand.Uint32())
	}

	return generator
}

func (g *identificationGenerator) next(source, destination net.IP) uint16 {
	var key [8]byte
	copy(key[0:4], source.To4())
	copy(key[4:8], destination.To4())
	sum := maphash.Bytes(g.seed, key[:])

	offset := uint16(sum >> 48)
	counter := &g.counters[sum%identificationCounters]
	return offset + uint16(counter.Add(1))
}
