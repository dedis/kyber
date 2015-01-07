package ed25519

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/sha3"
	"hash"
)

type suiteEd25519 struct {
	Curve
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
	iv := make([]byte, 16)
	return cipher.NewCTR(aes, iv)
}

// SHA3/SHAKE128 sponge
func (s *suiteEd25519) Sponge() abstract.Sponge {
	return sha3.NewSponge128()
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) abstract.Suite {
	suite := new(suiteEd25519)
	return suite
}
