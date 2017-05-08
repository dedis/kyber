package edwards25519

import (
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/cipher/sha3"
)

// NOTE: This structure is not removed so this brings the questions of naming and
// consistency:
// + what is a suite ? why would we call it a suite in this package and not something else
// in curve25519 etc ?
// + how do I know which method to implement ? For example. we'll want to add
// ed448 to the our list, so we'll need to lookup here to see which methods
// ed448 is supposed to implement to be sure one can ecchange edwards25519 and
// edwards448 without any issues.
// The Suite interface solves these issues by defining the common set of method
// that be implemented (exactly as this `suiteed25519` suggests).
type suiteEd25519 struct {
	Curve
}

// SHA256 hash function
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// SHA3/SHAKE128 Sponge Cipher
func (s *suiteEd25519) Cipher(key []byte, options ...interface{}) crypto.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *suiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return crypto.SuiteRead(s, r, objs)
}

func (s *suiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return crypto.SuiteWrite(s, w, objs)
}

func (s *suiteEd25519) New(t reflect.Type) interface{} {
	return crypto.SuiteNew(s, t)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) *suiteEd25519 {
	suite := new(suiteEd25519)
	return suite
}
