package nist

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/cipher/sha3"
	"github.com/dedis/kyber/util/random"
)

type suite128 struct {
	p256
}

// SHA256 hash function
func (s *suite128) Hash() hash.Hash {
	return sha256.New()
}

// SHA3/SHAKE128 Sponge Cipher
func (s *suite128) Cipher(key []byte, options ...interface{}) kyber.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *suite128) Read(r io.Reader, objs ...interface{}) error {
	return kyber.SuiteRead(s, r, objs)
}

func (s *suite128) Write(w io.Writer, objs ...interface{}) error {
	return kyber.SuiteWrite(s, w, objs)
}

func (s *suite128) New(t reflect.Type) interface{} {
	return kyber.SuiteNew(s, t)
}

func (s *suite128) NewKey(rand cipher.Stream) kyber.Scalar {
	if rand == nil {
		rand = random.Stream
	}
	return s.Scalar().Pick(rand)
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve.
func NewAES128SHA256P256() *suite128 {
	suite := new(suite128)
	suite.p256.Init()
	return suite
}
