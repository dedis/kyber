// Package blake2xs provides an implementation of kyber.XOF based on the
// Blake2xs construction.
package blake2xs

import (
	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/blake2s"
)

type xof struct {
	impl blake2s.XOF
	seed []byte
	// key is here to not make excess garbage during repeated calls
	// to XORKeyStream.
	key []byte
}

// New creates a new XOF using the blake2s hash.
func New(seed []byte) kyber.XOF {
	seed1 := seed
	var seed2 []byte
	if len(seed) > blake2s.Size {
		seed1 = seed[0:blake2s.Size]
		seed2 = seed[blake2s.Size:]
	}

	b, err := blake2s.NewXOF(blake2s.OutputLengthUnknown, seed1)
	if err != nil {
		panic("blake2s.NewXOF should not return error: " + err.Error())
	}

	_, err = b.Write(seed2)
	if err != nil {
		panic("blake2s.XOF.Write should not return error: " + err.Error())
	}

	seedCopy := make([]byte, len(seed2))
	copy(seedCopy, seed2)

	return &xof{impl: b, seed: seedCopy}
}

func (x *xof) Clone() kyber.XOF {
	return &xof{impl: x.impl.Clone()}
}

func (x *xof) Read(dst []byte) (int, error) {
	return x.impl.Read(dst)
}

func (x *xof) Write(src []byte) (int, error) {
	return x.impl.Write(src)
}

func (x *xof) Reseed() {
	// Use New to create a new one seeded with output from the old one.
	if len(x.key) < 128 {
		x.key = make([]byte, 128)
	} else {
		x.key = x.key[0:128]
	}
	x.Read(x.key)
	y := New(x.key)
	// Steal the XOF implementation, and put it inside of x.
	x.impl = y.(*xof).impl
}

func (x *xof) Reset() {
	x.impl.Reset()
	x.impl.Write(x.seed)
}

func (x *xof) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst too short")
	}
	if len(x.key) < len(src) {
		x.key = make([]byte, len(src))
	} else {
		x.key = x.key[0:len(src)]
	}

	n, err := x.Read(x.key)
	if err != nil {
		panic("blake xof error: " + err.Error())
	}
	if n != len(src) {
		panic("short read on key")
	}

	for i := range src {
		dst[i] = src[i] ^ x.key[i]
	}
}
