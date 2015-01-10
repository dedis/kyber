package cipher

import (
	"crypto/cipher"
)

// Wrap a Message Cipher to implement a legacy Stream Cipher.
func NewStream(cipher Cipher) cipher.Stream {
	return &cipherStream{cipher}
}

type cipherStream struct {
	c Cipher
}

func (cs *cipherStream) XORKeyStream(dst,src []byte) {
	cs.c.Encrypt(dst, src[:len(dst)], More)
}

