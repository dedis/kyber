// Since that package does not implement constant time arithmetic operations
// yet, it must be compiled with the "vartime" compilation flag.

// +build vartime

package curve25519

import (
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/fixbuf"
	"github.com/dedis/kyber"

	"github.com/dedis/kyber/group/internal/marshalling"
	"github.com/dedis/kyber/xof/blake"
)

type SuiteEd25519 struct {
	ProjectiveCurve
}

// SHA256 hash function
func (s *SuiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

func (s *SuiteEd25519) XOF(seed []byte) kyber.XOF {
	return blake.New(seed)
}

func (s *SuiteEd25519) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *SuiteEd25519) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

func (s *SuiteEd25519) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519(fullGroup bool) *SuiteEd25519 {
	suite := new(SuiteEd25519)
	suite.Init(Param25519(), fullGroup)
	return suite
}
