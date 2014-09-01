package edwards

import (
	"hash"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"dissent/crypto"
)

type suiteEd25519 struct {
	ProjectiveCurve
} 
// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suiteEd25519) HashLen() int { return sha256.Size }
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suiteEd25519) KeyLen() int { return 16 }
func (s *suiteEd25519) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func newAES128SHA256Ed25519() crypto.Suite {
	suite := new(suiteEd25519)
	suite.Init(Param25519())
	return suite
}

