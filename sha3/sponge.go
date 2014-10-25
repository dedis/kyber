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
)

type sponge struct {
	// Generic sponge components.
	a	[25]uint64	// main state of the sponge
	full	bool		// true if state contains unconsumed output

	rate	int		// the number of bytes of state to use
	keyLen	int		// minimum key length for full security

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

// BlockSize returns the rate of sponge underlying this hash function.
func (d *sponge) BlockSize() int { return d.rate }

// Size returns the output size of the hash function in bytes.
func (d *sponge) KeyLen() int { return d.keyLen }

// Clone the sponge state
func (d *sponge) Clone() abstract.SpongeCipher {
	c := *d
	return &c
}

// xorIn xors a block into the state, byte-swapping into little-endian.
// Returns the remainder of the source buffer.
func (d *sponge) xorIn(src []byte) {
	n := len(src) / 8
	for i := 0; i < n; i++ {
		a := binary.LittleEndian.Uint64(src)
		d.a[i] ^= a
		src = src[8:]
	}
}

// copyOut copies ulint64s to a byte buffer.
func (d *sponge) copyOut(b []byte) {
	for i := 0; len(b) > 0; i++ {
		binary.LittleEndian.PutUint64(b, d.a[i])
		b = b[8:]
	}
}

// xorOut encrypts exactly one block from src into dst,
// by XORing with the current cipherstream buf.
// If src is nil, behaves as if src were a block of 0 bytes.
func (d *sponge) xorOut(dst,src []byte) {
	n := d.rate
	var buf [maxRate]byte
	d.copyOut(buf[:n])
	if src == nil {
		copy(dst,buf[:n])
	} else {
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ buf[i]
		}
	}
}

// Absorb input blocks
func (d *sponge) absorbBlocks(src []byte) {
	n := d.rate
	for len(src) > 0 {
		d.xorIn(src[:n])
		keccakF1600(&d.a)		// absorb input
		src = src[n:]
	}
	d.full = true				// we can use final output

	if len(src) != 0 {
		panic("partial messages must be block granularity")
	}
}

// Squeeze output blocks
func (d *sponge) squeezeBlocks(dst []byte) {
	n := d.rate
	for len(dst) > 0 {
		if !d.full {
			keccakF1600(&d.a)
		}
		d.xorOut(dst[:n],nil)		// produce output stream
		d.full = false			// consume cipherstream buf
		dst = dst[n:]
	}
	if len(dst) != 0 {
		panic("partial messages must be block granularity")
	}
}

// Encrypt or decrypt complete blocks in duplex mode
func (d *sponge) duplexBlocks(dst,src []byte, encrypt bool) {

	if len(dst) != len(src) {
		panic("Sponge requires same-length src and dst")
	}

	// Pre-fill the cipherstream output buffer if necessary.
	n := d.rate
	if !d.full {
		keccakF1600(&d.a)
		d.full = true
	}

	// Simultaneously process input and output blocks
	for len(dst) > 0 {
		if encrypt {
			d.xorIn(src[:n])	// absorb before encryption
			d.xorOut(dst[:n],src[:n])	// XOR-encrypt
		} else {
			d.xorOut(dst[:n],src[:n])	// XOR-decrypt
			d.xorIn(dst[:n])	// absorb after decryption
		}

		// Consume input and produce next output block
		keccakF1600(&d.a)		// absorb and squeeze

		src = src[n:]
		dst = dst[n:]
	}

	if len(src) != 0 || len(dst) != 0 {
		panic("partial messages must be block granularity")
	}
}

// Process complete blocks
func (d *sponge) blocks(dst,src []byte, encrypt bool) {

	if src == nil {
		d.squeezeBlocks(dst)
	} else if dst == nil {
		d.absorbBlocks(src)
	} else {
		d.duplexBlocks(dst,src,encrypt)
	}
}

// padIn appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
// The dst buf must be exactly one block long,
// and the src buf must be strictly less than one block.
func (d *sponge) padIn(dst,src []byte) {

	// Copy the partial input
	n := copy(dst,src)

	// Pad with this instance's domain-separator bits. We know that there's
	// at least one byte of space in d.buf because, if it were full,
	// permute would have been called to empty it. dsbyte also contains the
	// first one bit for the padding. See the comment in the state struct.
	dst[n] = d.dsbyte
	n++

	// Fill out the remainder of the block with zeros
	for ; n < d.rate; n++ {
		dst[n] = 0
	}

	// This adds the final one bit for the padding. Because of the way that
	// bits are numbered from the LSB upwards, the final bit is the MSB of
	// the last byte.
	dst[n-1] ^= 0x80
}

// Encrypt or decrypt a variable-length, padding message (or the end of one)
func (d *sponge) message(dst,src []byte, encrypt bool) {

	l := len(src)
	if l == 0 {
		l = len(dst)
	} else if dst != nil && l != len(dst) {
		panic("Sponge requires same-length src and dst")
	}

	// Process whole blocks
	if l >= d.rate {
		bl := (l / d.rate) * d.rate
		var bdst,bsrc []byte
		if src != nil {
			bsrc = src[:bl]
			src = src[bl:]
		}
		if dst != nil {
			bdst = dst[:bl]
			dst = dst[bl:]
		}
		d.blocks(bdst,bsrc,encrypt)
	}

	// Pad the final partial input and/or output block
	var fsrc []byte
	if src != nil {
		var sbuf [maxRate]byte
		fsrc = sbuf[:d.rate]
		d.padIn(fsrc, src)
	}
	if dst != nil {
		var dbuf [maxRate]byte
		fdst := dbuf[:d.rate]
		d.blocks(fdst,fsrc,encrypt)
		copy(dst,fdst)
	} else {
		d.blocks(nil,fsrc,encrypt)	// just absorb input
	}
}

func (d *sponge) Encrypt(dst,src []byte, more bool) {
	if more {
		d.blocks(dst,src,true)
	} else {
		d.message(dst,src,true)
	} 
}

func (d *sponge) Decrypt(dst,src []byte, more bool) {
	if more {
		d.blocks(dst,src,false)
	} else {
		d.message(dst,src,false)
	} 
}

