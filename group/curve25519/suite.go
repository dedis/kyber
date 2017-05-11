package curve25519

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/util/random"
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
func (s *SuiteEd25519) Cipher(key []byte, options ...interface{}) crypto.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *SuiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return crypto.SuiteRead(s, r, objs)
}

func (s *SuiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return crypto.SuiteWrite(s, w, objs)
}

func (s *SuiteEd25519) New(t reflect.Type) interface{} {
	return crypto.SuiteNew(s, t)
}

func (s *SuiteEd25519) NewKey(rand cipher.Stream) crypto.Scalar {
	if rand == nil {
		rand = random.Stream
	}
	return s.Scalar().Pick(rand)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) *SuiteEd25519 {
	suite := new(SuiteEd25519)
	suite.Init(Param25519(), fullGroup)
	return suite
}
