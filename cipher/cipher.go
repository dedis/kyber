package cipher

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
)

type Stream cipher.Stream
type Block cipher.Block


// CipherRead provides a generic implementation of Cipher.Read.
func CipherRead(cipher abstract.Cipher, dst []byte) (n int, err error) {
	cipher.Crypt(dst, nil, abstract.More{})
	return len(dst), nil
}

// CipherWrite provides a generic implementation of Cipher.Write.
func CipherWrite(cipher abstract.Cipher, src []byte) (n int, err error) {
	cipher.Crypt(nil, src, abstract.More{})
	return len(src), nil
}

// CipherXORKeyStream provides a generic implementation of Cipher.XORKeyStream.
func CipherXORKeyStream(cipher abstract.Cipher, dst, src []byte) {
	cipher.Crypt(dst[:len(src)], src, abstract.More{})
}

