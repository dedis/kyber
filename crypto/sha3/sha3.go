// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import (
	"encoding/binary"
)

// spongeDirection indicates the direction bytes are flowing through the sponge.
type spongeDirection int

const (
	spongeIdle spongeDirection = iota	// between messages
	spongeAbsorbing				// absorbing input message text
	spongeSqueezing				// squeezing out a cipherstream
)

const (
	// maxRate is the maximum size of the internal buffer. SHAKE-256
	// currently needs the largest buffer.
	maxRate = 168
)

type state struct {
	// Generic sponge components.
	a    [25]uint64 // main state of the hash
	buf  []byte     // points into storage
	rate int        // the number of bytes of state to use

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
	storage [maxRate]byte

	// Specific to SHA-3 and SHAKE.
	fixedOutput bool            // whether this is a fixed-ouput-length instance
	outputLen   int             // the default output size in bytes
	state       spongeDirection // current direction of the sponge
}

// BlockSize returns the rate of sponge underlying this hash function.
func (d *state) BlockSize() int { return d.rate }

// Size returns the output size of the hash function in bytes.
func (d *state) Size() int { return d.outputLen }

// Reset clears the internal state by zeroing the sponge state and
// the byte buffer, and setting Sponge.state to absorbing.
func (d *state) Reset() {
	// Zero the permutation's state.
	for i := range d.a {
		d.a[i] = 0
	}
	d.state = spongeAbsorbing
	d.buf = d.storage[:0]
}

func (d *state) Set(src Sponge) Sponge {
	*d = *src.(*state)
	switch d.state {
	case spongeAbsorbing:
		d.buf = d.storage[:len(d.buf)]
	case spongeSqueezing:
		d.buf = d.storage[d.rate-cap(d.buf) : d.rate]
	}
	return d
}

// xorIn xors a buffer into the state, byte-swapping to
// little-endian as necessary; it returns the number of bytes
// copied, including any zeros appended to the bytestring.
func (d *state) xorIn(buf []byte) {
	n := len(buf) / 8

	for i := 0; i < n; i++ {
		a := binary.LittleEndian.Uint64(buf)
		d.a[i] ^= a
		buf = buf[8:]
	}
	if len(buf) != 0 {
		// XOR in the last partial ulint64.
		a := uint64(0)
		for i, v := range buf {
			a |= uint64(v) << uint64(8*i)
		}
		d.a[n] ^= a
	}
}

// copyOut copies ulint64s to a byte buffer.
func (d *state) copyOut(b []byte) {
	for i := 0; len(b) >= 8; i++ {
		binary.LittleEndian.PutUint64(b, d.a[i])
		b = b[8:]
	}
}

// permute applies the KeccakF-1600 permutation. It handles
// any input-output buffering.
func (d *state) permute(in,out []byte) {
	if in != nil {
		// If we're absorbing, we need to xor the input into the state
		// before applying the permutation.
		d.xorIn(in)
	}

	keccakF1600(&d.a)

	if out != nil {
		// If we're squeezing, we need to apply the permutatin before
		// copying more output.
		d.copyOut(out)
	}
}

// pads appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
func (d *state) padAndPermute(dsbyte byte) {
	if d.buf == nil {
		d.buf = d.storage[:0]
	}
	// Pad with this instance's domain-separator bits. We know that there's
	// at least one byte of space in d.buf because, if it were full,
	// permute would have been called to empty it. dsbyte also contains the
	// first one bit for the padding. See the comment in the state struct.
	d.buf = append(d.buf, dsbyte)
	zerosStart := len(d.buf)
	d.buf = d.storage[:d.rate]
	for i := zerosStart; i < d.rate; i++ {
		d.buf[i] = 0
	}
	// This adds the final one bit for the padding. Because of the way that
	// bits are numbered from the LSB upwards, the final bit is the MSB of
	// the last byte.
	d.buf[d.rate-1] ^= 0x80
	// Apply the permutation
	d.permute(d.buf,d.buf)
	d.state = spongeSqueezing
}

// Write absorbs more data into the hash's state.
func (d *state) Write(p []byte) (written int, err error) {
	if d.state != spongeAbsorbing {
		d.state = spongeAbsorbing
		d.buf = d.storage[:0]
	}
	written = len(p)

	for len(p) > 0 {
		if len(d.buf) == 0 && len(p) >= d.rate {
			// The fast path; absorb a full "rate" bytes of input
			// and apply the permutation.
			d.xorIn(p[:d.rate])
			p = p[d.rate:]
			keccakF1600(&d.a)
		} else {
			// The slow path; buffer the input until we can fill
			// the sponge, and then xor it in.
			todo := d.rate - len(d.buf)
			if todo > len(p) {
				todo = len(p)
			}
			d.buf = append(d.buf, p[:todo]...)
			p = p[todo:]

			// If the sponge is full, apply the permutation.
			if len(d.buf) == d.rate {
				d.permute(d.buf,nil)
				d.buf = d.storage[:0]
			}
		}
	}

	return
}

// Read squeezes an arbitrary number of bytes from the sponge.
func (d *state) Read(dst []byte) (n int, err error) {
	n = len(dst)
	d.XORKeyStream(dst, nil)
	return
}

func (d *state) XORKeyStream(dst, src []byte) {

	// If we're still absorbing, pad and apply the permutation.
	if d.state != spongeSqueezing {
		d.padAndPermute(d.dsbyte)
	}

	// Now, do the squeezing.
	for len(dst) > 0 {
		// Apply the permutation if we've squeezed the sponge dry.
		if len(d.buf) == 0 {
			d.buf := d.storage[:d.rate]
			d.permute(nil,d.buf)
		}

		// Copy or XOR the output cipherstream data.
		var n int
		if src == nil {
			n := copy(dst, d.buf)
		} else {
			n = len(d.buf)
			if n > len(dst) {
				n = len(dst)
			}
			for i := 0; i < n; i++ {
				dst[i] = src[i] ^ d.buf[i]
			}
			src = src[n:]
		}
		d.buf = d.buf[n:]
		dst = dst[n:]
	}
}

// Duplex-mode sponge construction, more-or-less as described in:
// http://sponge.noekeon.org/SpongeDuplex.pdf
func (d *state) duplex(dst,src []byte, encrypt bool) {

	// Finish absorbing any prior message.
	if d.state != spongeSqueezing {
		d.padAndPermute(d.dsbyte)
	}
	if len(d.buf) < d.rate {
		// Discard any prior partially-consumed output
		// and get a complete, propoperly-aligned block.
		d.buf = d.storage[:d.rate]
		d.permute(nil,d.buf)
	}

	// Copy the source if it aliases the destination.
	if src == dst {
		tmp := make([]byte, len(src))
		copy(tmp, src)
		src = tmp
	}

	// Concurrently absorb and squeeze a block at a time.
	for len(dst) > 0 || absorb != nil {

		// Consume whatever we need of the already-squeezed output
		var n int
		if src == nil {
			n = copy(dst, d.buf)
		} else {
			n = len(d.buf)
			if n > len(dst) {
				n = len(dst)
			}
			for i := 0; i < n; i++ {
				dst[i] = src[i] ^ d.buf[i]
			}
			src = src[n:]
		}
		dst = dst[n:]

		// Absorb input, if there is input to absorb,
		// and produce the next block of cipherstream output.
		if len(absorb) >= d.rate {	// absorb complete block
			inbuf := absorb[:d.rate]
			d.buf = d.storage[:d.rate]
			d.permute(inbuf,d.buf)
		} else if absorb != nil {	// absorb final padded block
			n := copy(d.storage[:],absorb)
			d.buf = d.storage[:n]
			d.padAndPermute(d.dsbyte)
			absorb = nil
		} else if len(dst) > 0 {	// nothing to absorb
			d.buf = d.storage[:d.rate]
			d.permute(nil,d.buf)
		}
	}
}

// Encrypt a message at src into an equal-size ciphertext at dst,
// while absorbing all of the message's bits into the sponge's state.
func (d *state) Encrypt(dst,src []byte) {
	d.duplex(dst, src, true)
}

// Decrypt a ciphertext at src into an equal-size plaintext message at dst,
// while absorbing all of the message's bits into the sponge's state.
func (d *state) Decrypt(dst,src []byte) {
	d.duplex(dst, src, false)
}

// Sum applies padding to the hash state and then squeezes out the desired
// number of output bytes.
func (d *state) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing
	// and summing.
	dup := state{}
	dup.Set(d)
	hash := make([]byte, dup.outputLen)
	dup.Read(hash)
	return append(in, hash...)
}



