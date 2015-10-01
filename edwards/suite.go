package edwards

import (
	"crypto/sha256"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
	"hash"
	"io"
	"reflect"
	//"github.com/dedis/crypto/edwards/ed25519"
)

type suiteEd25519 struct {
	//ed25519.Curve
	ProjectiveCurve
}

// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// SHA3/SHAKE128 Sponge Cipher
func (s *suiteEd25519) Cipher(key []byte, options ...interface{}) abstract.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *suiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return abstract.SuiteRead(s, r, objs)
}

func (s *suiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return abstract.SuiteWrite(s, w, objs)
}

func (s *suiteEd25519) New(t reflect.Type) interface{} {
	return abstract.SuiteNew(s, t)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) abstract.Suite {
	suite := new(suiteEd25519)
	suite.Init(Param25519(), fullGroup)
	return suite
}
