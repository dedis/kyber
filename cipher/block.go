package cipher

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
	"hash"
)

// Construct a general message Cipher
// from a Block cipher and a cryptographic Hash.
func FromBlock(newCipher func(key []byte) (cipher.Block, error),
	newHash func() hash.Hash, blockLen, keyLen, hashLen int,
	key []byte, options ...interface{}) abstract.Cipher {

	newStream := func(key []byte) cipher.Stream {
		b, err := newCipher(key)
		iv := make([]byte, b.BlockSize())
		if err != nil {
			panic(err.Error())
		}
		return cipher.NewCTR(b, iv)
	}
	return FromStream(newStream, newHash, blockLen, keyLen, hashLen,
			key, options...)
}
