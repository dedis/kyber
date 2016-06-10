package util

import "crypto/cipher"

type constantStream struct {
	seed []byte
}

// ConstantStream is a cipher.Stream which always returns
// the same value.
func ConstantStream(buff []byte) cipher.Stream {
	return &constantStream{buff}
}

// XORKexStream implements the cipher.Stream interface
func (cs *constantStream) XORKeyStream(dst, src []byte) {
	copy(dst, cs.seed)
}
