package filippo_ed25519

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"go.dedis.ch/fixbuf"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/internal/marshalling"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// SuiteFilippoEd25519 implements some basic functionalities such as Group, HashFactory,
// and XOFFactory.
type SuiteFilippoEd25519 struct {
	Curve
	r cipher.Stream
}

// Hash returns a newly instanciated sha256 hash function.
func (s *SuiteFilippoEd25519) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns an XOF which is implemented via the Blake2b hash.
func (s *SuiteFilippoEd25519) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s *SuiteFilippoEd25519) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs...)
}

func (s *SuiteFilippoEd25519) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// New implements the kyber.Encoding interface
func (s *SuiteFilippoEd25519) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteFilippoEd25519) RandomStream() cipher.Stream {
	if s.r != nil {
		return s.r
	}
	return random.New()
}

// NewBlakeSHA256Ed25519 returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
// It produces cryptographically random numbers via package crypto/rand.
func NewBlakeSHA256FilippoEd25519() *SuiteFilippoEd25519 {
	suite := new(SuiteFilippoEd25519)
	return suite
}

// NewBlakeSHA256Ed25519WithRand returns a cipher suite based on package
// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
// It produces cryptographically random numbers via the provided stream r.
func NewBlakeSHA256FilippoEd25519WithRand(r cipher.Stream) *SuiteFilippoEd25519 {
	suite := new(SuiteFilippoEd25519)
	suite.r = r
	return suite
}
