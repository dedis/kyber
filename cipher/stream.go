package cipher

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
)

// Wrap a Message Cipher to implement a legacy Stream Cipher.
func NewStream(cipher abstract.Cipher) cipher.Stream {
	return &cipherStream{cipher}
}

type cipherStream struct {
	c abstract.Cipher
}

func (cs *cipherStream) XORKeyStream(dst,src []byte) {
	cs.c.Crypt(dst, src[:len(dst)], abstract.More{})
}

