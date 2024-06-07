package kilic

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	bls12381 "github.com/kilic/bls12-381"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

type Suite struct {
	domainG1 []byte
	domainG2 []byte
}

// NewBLS12381Suite is the same as calling NewBLS12381SuiteWithDST(nil, nil): it uses the default domain separation
// tags for its Hash To Curve functions.
func NewBLS12381Suite() pairing.Suite {
	return &Suite{}
}

// NewBLS12381SuiteWithDST allows you to set your own domain separation tags to be used by the Hash To Curve functions.
// Since the DST shouldn't be 0 len, if you provide nil or a 0 len byte array, it will use the RFC default values.
func NewBLS12381SuiteWithDST(DomainG1, DomainG2 []byte) pairing.Suite {
	return &Suite{domainG1: DomainG1, domainG2: DomainG2}
}

func (s *Suite) SetDomainG1(dst []byte) {
	s.domainG1 = dst
}

func (s *Suite) G1() kyber.Group {
	return NewGroupG1(s.domainG1...)
}

func (s *Suite) SetDomainG2(dst []byte) {
	s.domainG2 = dst
}

func (s *Suite) G2() kyber.Group {
	return NewGroupG2(s.domainG2...)
}

func (s *Suite) GT() kyber.Group {
	return NewGroupGT()
}

// ValidatePairing implements the `pairing.Suite` interface
func (s *Suite) ValidatePairing(p1, p2, p3, p4 kyber.Point) bool {
	e := bls12381.NewEngine()
	// we need to clone the point because of https://github.com/kilic/bls12-381/issues/37
	// in order to avoid risks of race conditions.
	g1point := new(bls12381.PointG1).Set(p1.(*G1Elt).p)
	g2point := new(bls12381.PointG2).Set(p2.(*G2Elt).p)
	g1point2 := new(bls12381.PointG1).Set(p3.(*G1Elt).p)
	g2point2 := new(bls12381.PointG2).Set(p4.(*G2Elt).p)
	e.AddPair(g1point, g2point)
	e.AddPairInv(g1point2, g2point2)
	return e.Check()
}

func (s *Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	e := bls12381.NewEngine()
	g1point := p1.(*G1Elt).p
	g2point := p2.(*G2Elt).p
	return newGT(e.AddPair(g1point, g2point).Result())
}

// New implements the kyber.Encoding interface.
func (s *Suite) New(t reflect.Type) interface{} {
	panic("Suite.Encoding: deprecated in kyber")
}

// Read is the default implementation of kyber.Encoding interface Read.
func (s *Suite) Read(r io.Reader, objs ...interface{}) error {
	panic("Suite.Read(): deprecated in kyber")
}

// Write is the default implementation of kyber.Encoding interface Write.
func (s *Suite) Write(w io.Writer, objs ...interface{}) error {
	panic("Suite.Write(): deprecated in kyber")
}

// Hash returns a newly instantiated sha256 hash function.
func (s *Suite) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newly instantiated blake2xb XOF function.
func (s *Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (s *Suite) RandomStream() cipher.Stream {
	return random.New()
}
