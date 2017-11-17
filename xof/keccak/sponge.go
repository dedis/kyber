// Package keccak implements a cryptographic sponge using the Keccak permutation.
package keccak

import (
	"encoding/binary"

	"github.com/dedis/kyber"
)

const (
	// stateBits is the total state length of the sponge, in bits
	stateBits = 1600
	// stateBytes is the total state length of the sponge, in bytes
	stateBytes = 1600 / 8
)

type sponge struct {
	// Generic sponge components.
	a    [stateBits / 64]uint64 // main state of the sponge
	rate int                    // number of state bytes to use for data
}

// Rate returns the sponge's data block size (rate).
func (d *sponge) Rate() int { return d.rate }

// Capacity returns the sponge's secret state capacity.
func (d *sponge) Capacity() int { return stateBytes - d.rate }

func (d *sponge) Clone() kyber.Sponge {
	var dd = *d
	return &dd
}

func (d *sponge) Transform(dst, src []byte) {
	a := d.a[:]
	for len(src) > 0 {
		a[0] ^= binary.LittleEndian.Uint64(src)
		src = src[8:]
		a = a[1:]
	}

	keccakF1600(&d.a) // permute state

	a = d.a[:]
	for len(dst) > 0 {
		binary.LittleEndian.PutUint64(dst, a[0])
		a = a[1:]
		dst = dst[8:]
	}
}

// NewKeccak1024 creates a Keccak sponge primitive with 1024-bit capacity.
func NewKeccak1024() kyber.Sponge { return &sponge{rate: 72} }
