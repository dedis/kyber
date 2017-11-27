// Package keccak provides an implementation of kyber.XOF based on the
// Shake256 hash.
package keccak

import (
	"github.com/dedis/kyber"
	"golang.org/x/crypto/sha3"
)

type xof struct {
	sh  sha3.ShakeHash
	key []byte
}

// New creates a new XOF using the Shake256 hash.
func New(seed []byte) kyber.XOF {
	sh := sha3.NewShake256()
	sh.Write(seed)
	return &xof{sh: sh}
}

func (x *xof) KeySize() int {
	// From https://github.com/golang/crypto/blob/1b32d8b50a20d8fb3f40d1d50cb9d75cd0135bc8/sha3/shake.go#L46
	return 136
}

func (x *xof) Clone() kyber.XOF {
	return &xof{sh: x.sh.Clone()}
}

func (x *xof) Reseed() {
	key := make([]byte, x.KeySize())
	x.Read(key)
	x.sh = sha3.NewShake256()
	x.sh.Write(key)
	return
}

func (x *xof) Read(dst []byte) (int, error) {
	return x.sh.Read(dst)
}

func (x *xof) Write(src []byte) (int, error) {
	return x.sh.Write(src)
}

func (x *xof) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst too short")
	}
	if len(x.key) < len(src) {
		x.key = make([]byte, len(src))
	}

	n, err := x.Read(x.key)
	if err != nil {
		panic("xof error getting key: " + err.Error())
	}
	if n != len(x.key) {
		panic("short read on key")
	}

	for i := range src {
		dst[i] = src[i] ^ x.key[i]
	}
}
