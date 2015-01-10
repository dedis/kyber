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

	// stateLen is the total state length of SHA3 rate+capacity.
	stateLen = 200
)

type sponge struct {
	// Generic sponge components.
	a	[25]uint64	// main state of the sponge
	rate	int		// number of state bytes to use for data
}

// Rate returns the sponge's data block size (rate).
func (d *sponge) Rate() int { return d.rate }

// Capacity returns the sponge's secret state capacity.
func (d *sponge) Capacity() int { return stateLen - d.rate }

// Clone the sponge state
func (d *sponge) Clone() abstract.Sponge {
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

func (d *sponge) Transform(dst,src,key []byte) {
	n := d.rate >> 3
	xorIn(d.a[:n], src)			// data block
	xorIn(d.a[n:], key)			// key material

	keccakF1600(&d.a)			// permute state

	a := d.a[:d.rate >> 3]
	for len(dst) >= 8 {
		binary.LittleEndian.PutUint64(dst, a[0])
		a = a[1:]
		dst = dst[8:]
	}
	if len(dst) > 0 {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], a[0])
		copy(dst,buf[:])
	}
}

func NewSponge128() abstract.Sponge { return &sponge{rate: 168} }
func NewSponge224() abstract.Sponge { return &sponge{rate: 144} }
func NewSponge256() abstract.Sponge { return &sponge{rate: 136} }
func NewSponge384() abstract.Sponge { return &sponge{rate: 104} }
func NewSponge512() abstract.Sponge { return &sponge{rate: 72} }

