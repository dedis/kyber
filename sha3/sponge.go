// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import (
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
)

const (
	// maxRate is the maximum size of the internal buffer. SHAKE-256
	// currently needs the largest buffer.
	maxRate = 168

	// stateLen is the total state length of BLAKE2b rate+capacity.
	stateLen = 200
)

type sponge struct {
	// Generic sponge components.
	a	[25]uint64	// main state of the sponge
	full	bool		// true if state contains unconsumed output
	rate	int		// number of state bytes to use for data
	hashLen	int		// recommended hash output length

	// dsbyte contains the "domain separation" value and the first bit of
	// the padding. In sections 6.1 and 6.2 of [1], the SHA-3 and SHAKE
	// functions are defined with bits appended to the message: SHA-3
	// functions have 01 and SHAKE functions have 1111. Because of the way
	// that bits are numbered from the LSB upwards, that ends up as
	// 00000010b and 00001111b, respectively. Then the padding rule from
	// section 5.1 is applied to pad to a multiple of the rate, which
	// involves adding a 1 bit, zero or more zero bits and then a final one
	// bit. The first one bit from the padding is merged into the dsbyte
	// value giving 00000110b (0x06) and 00011111b (0x1f), respectively.
	//
	// [1] http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf,
	dsbyte  byte
}

// BlockLen returns the sponge's data block size (rate).
func (d *sponge) BlockLen() int { return d.rate }

// StateLen returns the sponge's secret state capacity.
func (d *sponge) StateLen() int { return stateLen - d.rate }

// HashLen returns the recommended size of hashes produced for full security.
func (d *sponge) HashLen() int { return d.hashLen }

// Clone the sponge state
func (d *sponge) Clone() abstract.SpongeCipher {
	c := *d
	return &c
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

func (d *sponge) AbsorbBlock(src,key []byte, last bool) {
	n := d.rate >> 3
	xorIn(d.a[:n], src)			// data block
	xorIn(d.a[n:], key)			// key material
	keccakF1600(&d.a)			// permute state
	d.full = true				// have consumable output
}

func (d *sponge) SqueezeBlock(dst []byte) {
	if !d.full {
		keccakF1600(&d.a)		// permute state
	}
	src := d.a[:d.rate >> 3]
	for len(dst) >= 8 {
		binary.LittleEndian.PutUint64(dst, src[0])
		src = src[1:]
		dst = dst[8:]
	}
	if len(dst) > 0 {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], src[0])
		copy(dst,buf[:])
	}
	d.full = false
}

// Pad appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
// The dst buf must be exactly one block long,
// and the src buf must be strictly less than one block.
func (d *sponge) Pad(buf,src []byte) []byte {

	// Ensure that we have a sufficiently-long buffer,
	// allowing for us to append a 1-byte domain separator.
	// We'll produce just one block if len(src) < bs,
	// or two blocks if len(src) == bs.
	bs := d.rate
	l := bs
	if len(src) >= bs {
		l += bs
	}
	if len(buf) < l {
		buf = make([]byte, l)
	}

	// Copy the partial input
	n := copy(buf,src)

	// Pad with this instance's domain-separator bits.
	buf[n] = d.dsbyte
	n++

	// Fill out the remainder of the block with zeros
	for ; n < l; n++ {
		buf[n] = 0
	}

	// This adds the final one bit for the padding. Because of the way that
	// bits are numbered from the LSB upwards, the final bit is the MSB of
	// the last byte.
	buf[n-1] ^= 0x80

	return buf
}

