package curve25519

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
func (s *suiteEd25519) Cipher(key []byte, options ...interface{}) kyber.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *suiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return kyber.SuiteRead(s, r, objs)
}

func (s *suiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return kyber.SuiteWrite(s, w, objs)
}

func (s *suiteEd25519) New(t reflect.Type) interface{} {
	return kyber.SuiteNew(s, t)
}

func (s *suiteEd25519) NewKey(rand cipher.Stream) kyber.Scalar {
	if rand == nil {
		rand = random.Stream
	}
	return s.Scalar().Pick(rand)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) kyber.Suite {
	suite := new(suiteEd25519)
	suite.Init(Param25519(), fullGroup)
	return suite
}
