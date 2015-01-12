package edwards

import (
	"hash"
	"crypto/sha256"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
	//"github.com/dedis/crypto/edwards/ed25519"
)

type suiteEd25519 struct {
	//ed25519.Curve
	ProjectiveCurve
} 
// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suiteEd25519) HashLen() int { return sha256.Size }
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

func (s *suiteEd25519) KeyLen() int { return 16 }

// SHA3/SHAKE128 Sponge Cipher
func (s *suiteEd25519) Cipher(key []byte, options ...interface{}) abstract.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) abstract.Suite {
	suite := new(suiteEd25519)
	suite.Init(Param25519(), fullGroup)
	return suite
}

