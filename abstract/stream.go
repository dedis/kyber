// Package rand provides facilities for generating
// random or pseudorandom cryptographic objects.
package abstract

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// Stream represents an abstract stream of cryptographic (pseudo-)random bits.
// This struct is a wrapper for Go's standard cipher.Stream interface,
// providing a variety of convenience methods for generating
// various data types randomly or pseudo-randomly from a pseudo-random stream.
type Stream struct {
	cipher.Stream
}

// Choose a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func (s Stream) bits(bitlen uint, exact bool) []byte {
	b := make([]byte, (bitlen+7)/8)
	s.XORKeyStream(b, b)
	highbits := bitlen & 7
	if highbits != 0 {
		b[0] &= ^(0xff << highbits)
	}
	if exact {
		if highbits != 0 {
			b[0] |= 1 << (highbits - 1)
		} else {
			b[0] |= 0x80
		}
	}
	return b
}

// Choose a uniform random byte.
func (s Stream) Byte() byte {
	b := s.bits(8, false)
	return b[0]
}

// Choose a uniform random uint8.
func (s Stream) Uint8() uint8 {
	b := s.bits(8, false)
	return uint8(b[0])
}

// Choose a uniform random uint16.
func (s Stream) Uint16() uint16 {
	b := s.bits(16, false)
	return binary.BigEndian.Uint16(b)
}

// Choose a uniform random uint32.
func (s Stream) Uint32() uint32 {
	b := s.bits(32, false)
	return binary.BigEndian.Uint32(b)
}

// Choose a uniform random uint64.
func (s Stream) Uint64() uint64 {
	b := s.bits(64, false)
	return binary.BigEndian.Uint64(b)
}

// Choose a uniform random big.Int
// greater than zero but less than a given modulus.
func (s Stream) IntMod(mod *big.Int) *big.Int {
	bitlen := uint(mod.BitLen())
	i := new(big.Int)
	for {
		i.SetBytes(s.bits(bitlen, false))
		if i.Sign() > 0 && i.Cmp(mod) < 0 {
			return i
		}
	}
}

// Choose a uniform random big.Int having exactly a given number of bits:
// i.e., an integer between 2^(nbits-1) and 2^nbits-1 inclusive.
func (s Stream) Int(nbits int) *big.Int {
	return new(big.Int).SetBytes(s.bits(uint(nbits), true))
}

// Choose a uniform random n-byte slice.
func (s Stream) Bytes(n int) []byte {
	b := make([]byte, n)
	s.XORKeyStream(b, b)
	return b
}

// Read [pseudo-]random bytes from the underlying Stream,
// implementing the io.Reader interface.
func (s Stream) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	s.XORKeyStream(dst, dst)
	return len(dst), nil
}

type randstream struct {
}

func (r *randstream) XORKeyStream(dst, src []byte) {
	l := len(dst)
	if len(src) != l {
		panic("XORKeyStream: mismatched buffer lengths")
	}

	buf := make([]byte, l)
	n, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	if n < len(buf) {
		panic("short read on infinite random stream!?")
	}

	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ buf[i]
	}
}

// Standard virtual "stream cipher" that just generates
// fresh cryptographically strong random bits.
var RandomStream = Stream{new(randstream)}
