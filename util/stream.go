package util

import "crypto/cipher"

// ConstantStream is a cipher.Stream which always returns
// the same value. It is useful for generating secret from a
// slice of bytes, or for testing.
type ConstantStream struct {
	seed []byte
}

func NewConstantStream(buff []byte) cipher.Stream {
	return &ConstantStream{buff}
}

func (cs *ConstantStream) XORKeyStream(dst, src []byte) {
	copy(dst, cs.seed)
}
