// +build vartime

package curve25519

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/cipher/sha3"
	"gopkg.in/dedis/kyber.v1/util/random"
)

type SuiteEd25519 struct {
	//ed25519.Curve
	ProjectiveCurve
}

// XXX non-NIST ciphers?

// SHA256 hash function
func (s *SuiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// SHA3/SHAKE128 Sponge Cipher
func (s *SuiteEd25519) Cipher(key []byte, options ...interface{}) kyber.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *SuiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return kyber.SuiteRead(s, r, objs)
}

func (s *SuiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return kyber.SuiteWrite(s, w, objs)
}

func (s *SuiteEd25519) New(t reflect.Type) interface{} {
	return kyber.SuiteNew(s, t)
}

func (s *SuiteEd25519) NewKey(r cipher.Stream) kyber.Scalar {
	if r == nil {
		r = random.Stream
	}
	return s.Scalar().Pick(r)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) *SuiteEd25519 {
	suite := new(SuiteEd25519)
	suite.Init(Param25519(), fullGroup)
	return suite
}
