//go:build !constantTime

package edwards25519vartime

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"go.dedis.ch/fixbuf"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

// SuiteEd25519 is the suite for the Ed25519 curve
type SuiteEd25519 struct {
	ProjectiveCurve
}

// Hash returns the instance associated with the suite
func (s *SuiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// XOF creates the XOF associated with the suite
func (s *SuiteEd25519) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s *SuiteEd25519) Read(r io.Reader, objs ...any) error {
	return fixbuf.Read(r, s, objs...)
}

func (s *SuiteEd25519) Write(w io.Writer, objs ...any) error {
	return fixbuf.Write(w, objs...)
}

// New implements the kyber.encoding interface
func (s *SuiteEd25519) New(t reflect.Type) any {
	return marshalling.GroupNew(s, t)
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteEd25519) RandomStream() cipher.Stream {
	return random.New()
}

// NewBlakeSHA256Ed25519 returns a cipher suite based on package
// go.dedis.ch/kyber/v4/xof/blake2xb, SHA-256, and Ed25519.
//
// If fullGroup is false, then the group is the prime-order subgroup.
//
// The scalars created by this group implement kyber.Scalar's SetBytes
// method, interpreting the bytes as a big-endian integer, so as to be
// compatible with the Go standard library's compatible.Int type.
func NewBlakeSHA256Ed25519(fullGroup bool) *SuiteEd25519 {
	suite := new(SuiteEd25519)
	suite.Init(ParamEd25519(), fullGroup)
	return suite
}
