// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import (
	//"encoding/hex"
	"encoding/binary"
	"github.com/dedis/crypto/cipher"
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
func (d *sponge) Clone() cipher.Sponge {
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
	//odst := dst

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

	//println("Transform\n" + hex.Dump(src) + "->\n" + hex.Dump(odst))
}


// XXX rename NewKeccak256 etc. for consistency with SHA3 spec

// Create a Keccak sponge primitive with 256-bit capacity.
func NewKeccak256() cipher.Sponge { return &sponge{rate: 168} }

// Create a Keccak sponge primitive with 448-bit capacity.
func NewKeccak448() cipher.Sponge { return &sponge{rate: 144} }

// Create a Keccak sponge primitive with 512-bit capacity.
func NewKeccak512() cipher.Sponge { return &sponge{rate: 136} }

// Create a Keccak sponge primitive with 768-bit capacity.
func NewKeccak768() cipher.Sponge { return &sponge{rate: 104} }

// Create a Keccak sponge primitive with 1024-bit capacity.
func NewKeccak1024() cipher.Sponge { return &sponge{rate: 72} }

