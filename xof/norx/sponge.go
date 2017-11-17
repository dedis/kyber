// Package norx implements the experimental NORX cipher.
// For details on the NORX cipher see https://norx.io
// This package is very experimental and NOT for use in prodution systems.
//
// This is a fork of the NORX implementation in Go by Philipp Jovanovic,
// from http://github.com/daeinar/norx-go
package norx

import (
	"encoding/binary"

	"github.com/dedis/kyber"
)

// These have _ before them so that they are not exported. We keep them
// uppercase otherwise, so that we remain more faithful to the C reference
// version.
const (
	_NORX_W            = 64                                     // wordsize
	_NORX_R            = 4                                      // number of rounds
	_NORX_A            = _NORX_W * 4                            // tag size
	_NORX_D            = 1                                      // parallelism degree
	_R0, _R1, _R2, _R3 = 8, 19, 40, 63                          // rotation offsets
	_U0, _U1           = 0x243F6A8885A308D3, 0x13198A2E03707344 // initialisation constants
	_U2, _U3           = 0xA4093822299F31D0, 0x082EFA98EC4E6C89 // ...
	_U4, _U5           = 0xAE8858DC339325A1, 0x670A134EE52D7FA6 // ...
	_U6, _U7           = 0xC4316D80CD967541, 0xD21DFBF8B630B762 // ...
	_U8, _U9           = 0x375A18D261E7F892, 0x343D1F187D92285B // ...
	_WORDS_RATE        = 10                                     // number of words in the rate
	_WORDS_STATE       = 16                                     // ... in the state
	_BYTES_WORD        = _NORX_W / 8                            // byte size of a word
	_BYTES_RATE        = _WORDS_RATE * _BYTES_WORD              // ... of the rate
)

type state_t struct {
	s [_WORDS_STATE]uint64
}

func rotr(x, c uint64) uint64 {
	return (x>>c | x<<(_NORX_W-c))
}

func h(x, y uint64) uint64 {
	return (x ^ y) ^ ((x & y) << 1)
}

func g(a, b, c, d uint64) (uint64, uint64, uint64, uint64) {

	a = h(a, b)
	d = rotr(a^d, _R0)
	c = h(c, d)
	b = rotr(b^c, _R1)
	a = h(a, b)
	d = rotr(a^d, _R2)
	c = h(c, d)
	b = rotr(b^c, _R3)
	return a, b, c, d
}

func f(s []uint64) {

	// Column step
	s[0], s[4], s[8], s[12] = g(s[0], s[4], s[8], s[12])
	s[1], s[5], s[9], s[13] = g(s[1], s[5], s[9], s[13])
	s[2], s[6], s[10], s[14] = g(s[2], s[6], s[10], s[14])
	s[3], s[7], s[11], s[15] = g(s[3], s[7], s[11], s[15])
	// Diagonal step
	s[0], s[5], s[10], s[15] = g(s[0], s[5], s[10], s[15])
	s[1], s[6], s[11], s[12] = g(s[1], s[6], s[11], s[12])
	s[2], s[7], s[8], s[13] = g(s[2], s[7], s[8], s[13])
	s[3], s[4], s[9], s[14] = g(s[3], s[4], s[9], s[14])
}

func permute(state *state_t) {

	var s = state.s[:]
	for i := 0; i < _NORX_R; i++ {
		f(s)
	}
}

func load64(x []uint8) uint64 {
	return (uint64(x[0]) << 0) |
		(uint64(x[1]) << 8) |
		(uint64(x[2]) << 16) |
		(uint64(x[3]) << 24) |
		(uint64(x[4]) << 32) |
		(uint64(x[5]) << 40) |
		(uint64(x[6]) << 48) |
		(uint64(x[7]) << 56)
}

func setup(state *state_t, k []uint8, n []uint8) {

	var s = state.s[:]

	s[0] = _U0
	s[1] = load64(n[0:8])
	s[2] = load64(n[8:16])
	s[3] = _U1

	s[4] = load64(k[0:8])
	s[5] = load64(k[8:16])
	s[6] = load64(k[16:24])
	s[7] = load64(k[24:32])

	s[8] = _U2
	s[9] = _U3
	s[10] = _U4
	s[11] = _U5

	s[12] = _U6
	s[13] = _U7
	s[14] = _U8
	s[15] = _U9

	s[14] ^= (_NORX_R << 26) | (_NORX_D << 18) | (_NORX_W << 10) | _NORX_A
	permute(state)
}

func (s *state_t) Rate() int { return _BYTES_RATE }

func (s *state_t) Capacity() int {
	return (_WORDS_STATE - _WORDS_RATE) * _BYTES_WORD
}

func (s *state_t) Clone() kyber.Sponge {
	var ss = *s
	return &ss
}

func (s *state_t) Transform(dst, src []byte) {

	a := s.s[:]
	for len(src) > 0 {
		a[0] ^= binary.LittleEndian.Uint64(src)
		src = src[8:]
		a = a[1:]
	}

	permute(s)

	a = s.s[:]
	for len(dst) > 0 {
		binary.LittleEndian.PutUint64(dst, a[0])
		a = a[1:]
		dst = dst[8:]
	}
}

func NewSponge() kyber.Sponge {
	var zeros [32]uint8
	s := &state_t{}
	setup(s, zeros[:], zeros[:])
	return s
}
