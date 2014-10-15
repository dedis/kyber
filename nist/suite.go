package nist

import (
	"hash"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"github.com/dedis/crypto"
)

type suiteAES128SHA256P256 struct {
	p256
} 

// SHA256 hash function
func (s *suiteAES128SHA256P256) HashLen() int { return sha256.Size }
func (s *suiteAES128SHA256P256) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suiteAES128SHA256P256) KeyLen() int { return 16 }
func (s *suiteAES128SHA256P256) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve.
func NewAES128SHA256P256() crypto.Suite {
	suite := new(suiteAES128SHA256P256)
	suite.p256.Init()
	return suite
}

