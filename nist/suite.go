package nist

import (
	"hash"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
)

type suite128 struct {
	p256
} 

// SHA256 hash function
func (s *suite128) HashLen() int { return sha256.Size }
func (s *suite128) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suite128) KeyLen() int { return 16 }
func (s *suite128) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// SHA3/SHAKE128 Sponge Cipher
func (s *suite128) Cipher(options ...interface{}) abstract.Cipher {
	return sha3.NewShakeCipher128(options)
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve.
func NewAES128SHA256P256() abstract.Suite {
	suite := new(suite128)
	suite.p256.Init()
	return suite
}

