package util

import "crypto/cipher"

// ConstantStream is a cipher.Stream which always returns
// the same value.
type ConstantStream struct {
	seed []byte
}

// NewConstantStream returns a ConstantStream seeded with buff
func NewConstantStream(buff []byte) cipher.Stream {
	return &ConstantStream{buff}
}

// XORKexStream implements the cipher.Stream interface
func (cs *ConstantStream) XORKeyStream(dst, src []byte) {
	copy(dst, cs.seed)
}
