// Package rand provides facilities for generating
// cryptographic random or pseudorandom bits.
//
package random

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"golang.org/x/net/context"
)

// Stream represents a source of cryptographic (pseudo-)random bits,
// which we define as an alias of the standard cipher.Stream interface.
type Stream cipher.Stream

func randOrDefault(rand Stream) Stream {
	if rand == nil {
		rand = freshStream{}
	}
	return rand
}

// Choose a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func Bits(bitlen uint, exact bool, rand Stream) []byte {
	b := make([]byte, (bitlen+7)/8)
	rand.XORKeyStream(b, b)
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

// Choose a uniform random boolean
func Bool(rand Stream) bool {
	b := Bits(8, false, rand)
	return b[0]&1 != 0
}

// Choose a uniform random byte
func Byte(rand Stream) byte {
	b := Bits(8, false, rand)
	return b[0]
}

// Choose a uniform random uint8
func Uint8(rand Stream) uint8 {
	b := Bits(8, false, rand)
	return uint8(b[0])
}

// Choose a uniform random uint16
func Uint16(rand Stream) uint16 {
	b := Bits(16, false, rand)
	return binary.BigEndian.Uint16(b)
}

// Choose a uniform random uint32
func Uint32(rand Stream) uint32 {
	b := Bits(32, false, rand)
	return binary.BigEndian.Uint32(b)
}

// Choose a uniform random uint64
func Uint64(rand Stream) uint64 {
	b := Bits(64, false, rand)
	return binary.BigEndian.Uint64(b)
}

// Choose a uniform random big.Int less than a given modulus
func Int(mod *big.Int, rand Stream) *big.Int {
	bitlen := uint(mod.BitLen())
	i := new(big.Int)
	for {
		i.SetBytes(Bits(bitlen, false, rand))
		if i.Sign() > 0 && i.Cmp(mod) < 0 {
			return i
		}
	}
}

// Choose a random n-byte slice
func Bytes(n int, rand Stream) []byte {
	b := make([]byte, n)
	rand.XORKeyStream(b, b)
	return b
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

type freshStream struct {
}

func (r freshStream) XORKeyStream(dst, src []byte) {
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

// Return a source of fresh cryptographic random bits.
func Fresh() Stream {
	return freshStream{}
}

type contextKey struct{}

// Create a Context derived from the given parent context
// but configured with the given cryptographic group.
func Context(parent context.Context, random Stream) context.Context {
	return context.WithValue(parent, contextKey{}, random)
}

// Returns the random stream generator a context is configured with,
// or a fresh cryptographic random stream by default.
func Get(ctx context.Context) Stream {
	random, ok := ctx.Value(contextKey{}).(Stream)
	if !ok {
		random = freshStream{}
	}
	return random
}
