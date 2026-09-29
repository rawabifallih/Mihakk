package mutate

import (
	"crypto/sha256"
	"encoding/binary"
)

// stream is a deterministic byte source: SHA-256 in counter mode over a
// per-case key.
//
// math/rand is deliberately not used. Its output for a given seed is a
// property of the Go runtime, so a toolchain upgrade could silently change
// every mutation Mihakk generates and quietly invalidate saved cases. A
// hash-based stream is defined entirely by this file, which is what lets the
// engine promise that the same inputs regenerate the same requests.
type stream struct {
	key     [32]byte
	counter uint64
	buf     [32]byte
	off     int
}

func newStream(key [32]byte) *stream {
	// off past the end of buf forces a refill on first use.
	return &stream{key: key, off: 32}
}

func (s *stream) refill() {
	var block [40]byte
	copy(block[:32], s.key[:])
	binary.BigEndian.PutUint64(block[32:], s.counter)
	s.counter++
	s.buf = sha256.Sum256(block[:])
	s.off = 0
}

// byteN returns the next byte of the stream.
func (s *stream) byteN() byte {
	if s.off >= len(s.buf) {
		s.refill()
	}
	b := s.buf[s.off]
	s.off++
	return b
}

// bytes returns the next n bytes.
func (s *stream) bytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = s.byteN()
	}
	return out
}

// uint64n returns a uniform value in [0, n). Rejection sampling keeps the
// distribution even; a plain modulo would bias low values.
func (s *stream) uint64n(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	if n&(n-1) == 0 { // power of two
		return s.uint64() & (n - 1)
	}
	limit := ^uint64(0) - (^uint64(0) % n) - 1
	for {
		v := s.uint64()
		if v <= limit {
			return v % n
		}
	}
}

func (s *stream) uint64() uint64 {
	var b [8]byte
	for i := range b {
		b[i] = s.byteN()
	}
	return binary.BigEndian.Uint64(b[:])
}

// intn returns a uniform value in [0, n).
func (s *stream) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(s.uint64n(uint64(n)))
}

// pick returns a uniformly chosen element index for a list of length n.
func (s *stream) pick(n int) int { return s.intn(n) }

// bool returns a deterministic coin flip.
func (s *stream) boolean() bool { return s.byteN()&1 == 1 }
