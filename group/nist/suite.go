// +build vartime

package nist

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

type Suite128 struct {
	p256
}

// SHA256 hash function
func (s *Suite128) Hash() hash.Hash {
	return sha256.New()
}

func (s *Suite128) XOF(key []byte) kyber.XOF {
	return blake.New(key)
}

func (s *Suite128) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs)
}

func (s *Suite128) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

func (s *Suite128) New(t reflect.Type) interface{} {
	return marshalling.GroupNew(s, t)
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve.
func NewAES128SHA256P256() *Suite128 {
	suite := new(Suite128)
	suite.p256.Init()
	return suite
}
