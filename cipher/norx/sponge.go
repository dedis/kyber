// Package NORX implements the experimental NORX cipher.
// For details on the NORX cipher see https://norx.io
// This package is very experimental and NOT for use in prodution systems.
//
// This is a fork of the NORX implementation in Go by Philipp Jovanovic,
// from http://github.com/daeinar/norx-go
package norx

import (
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

func (s *state_t) Rate() int { return BYTES_RATE }

func (s *state_t) Capacity() int {
	return (WORDS_STATE - WORDS_RATE) * BYTES_WORD
}

func (s state_t) Clone() cipher.Sponge {
	return &s
}

func xorIn(dst []uint64, src []byte) {
	for len(src) >= 8 {
		dst[0] ^= binary.LittleEndian.Uint64(src)
		src = src[8:]
		dst = dst[1:]
	}
	if len(src) > 0 {
		var buf [8]byte
		copy(buf[:], src)
		dst[0] ^= binary.LittleEndian.Uint64(buf[:])
	}
}

func (s *state_t) Transform(dst, src, key []byte) {

	xorIn(s.s[:WORDS_RATE], src) // data block
	//xorIn(s.s[WORDS_RATE:], key) // key material

	permute(s)

	a := s.s[:WORDS_RATE]
	for len(dst) >= 8 {
		binary.LittleEndian.PutUint64(dst, a[0])
		a = a[1:]
		dst = dst[8:]
	}
	if len(dst) > 0 {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], a[0])
		copy(dst, buf[:])
	}
}

func newSponge() cipher.Sponge {
	var zeros [32]uint8
	s := &state_t{}
	setup(s, zeros[:], zeros[:]) // XXX initialize via options
	return s
}

// NewCipher creates a Cipher implementing the 64-4-1 mode of NORX.
func NewCipher(key []byte, options ...interface{}) abstract.Cipher {
	return cipher.NewSpongeCipher(newSponge(), key, options...)
}

