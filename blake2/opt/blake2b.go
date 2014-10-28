// Package blake2 provides a Go wrapper around an optimized, public domain
// implementation of BLAKE2.
// The cryptographic hash function BLAKE2 is an improved version of the SHA-3
// finalist BLAKE. Like BLAKE or SHA-3, BLAKE2 offers the highest security, yet
// is fast as MD5 on 64-bit platforms and requires at least 33% less RAM than
// SHA-2 or SHA-3 on low-end systems.
package opt

import (
	// #cgo CFLAGS: -O3
	// #include "blake2.h"
	"C"
	"unsafe"
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
)

const (
	blockLen = 128
	stateLen = 64
	hashLen = 64
)

// Minimal BLAKE2b compression function state.
type State struct {
	bs C.blake2b_state
	full bool
}

// Create a new sponge cipher based on BLAKE2b.
func NewState() *State {
	s := State{}
	C.blake2b_init(&s.bs, stateLen)
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
		copy(buf[:],src)
		dst[0] ^= binary.LittleEndian.Uint64(buf[:])
	}
}

// Absorb up to BlockLen data bytes from src,
// and up to StateLen bytes of state-indexing material from idx.
// The last flag indicates the last block of a padded message.
func (s *State) AbsorbBlock(src,idx []byte, last bool) {

	// Make sure the src is a complete block
	// (unless it's nil indicating no input at all, which is OK).
	if src != nil && len(src) < blockLen {
		buf := make([]byte, blockLen)
		copy(buf, src)
		src = buf
	}

	// Indexing material gets XORed into IV
	if idx != nil {
		h := (*[8]uint64)(unsafe.Pointer(&s.bs.h[0]))
		xorIn(h[:], idx)
	}

	C.blake2b_increment_counter(&s.bs, C.uint64_t(len(src)))
	if last {
		s.bs.f[0] = ^C.uint64_t(0)
	} else {
		s.bs.f[0] = 0
	}

	C.blake2b_compress(&s.bs, (*C.uint8_t)(unsafe.Pointer(&src[0])))

	s.full = true
}

// Squeeze up to BlockLen data bytes into dst,
// updating the state if no unconsumed output block is available.
func (s *State) SqueezeBlock(dst []byte) {
	if !s.full {
		s.AbsorbBlock(nil, nil, false)
	}

	buf := (*[blockLen]uint8)(unsafe.Pointer(&s.bs.buf[0]))
	copy(dst, buf[:])

	s.full = false
}

// Pad the variable-length input src, of size up to one block.
// BLAKE2 doesn't require any padding overhead bytes,
// since message length is indicated via side-band inputs.
func (s *State) Pad(buf,src []byte) []byte {
	return src
}

// Return the number of data bytes the sponge can aborb in one block.
func (s *State) BlockLen() int {
	return blockLen
}

// Return the sponge's secret state capacity in bytes.
func (s *State) StateLen() int {
	return stateLen
}

// Return the recommended size of hash outputs for full security.
func (s *State) HashLen() int {
	return stateLen
}

// Create a copy of this SpongeCipher with identical state
func (s *State) Clone() abstract.SpongeCipher {
	c := *s
	return &c
}

// Read the internal state to produce a standard BLAKE2b hash.
// This produces a different result than Sponge.Hash(),
// which is more secure against length-extension/reuse issues
// but incompatible with the BLAKE2b spec.
func (s *State) Hash(hash []byte) {
	h := (*[hashLen]byte)(unsafe.Pointer(&s.bs.h[0]))
	copy(hash, h[:])
}

