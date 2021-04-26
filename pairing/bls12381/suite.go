package bls12381

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	bls12381 "github.com/kilic/bls12-381"
	"go.dedis.ch/fixbuf"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// Suite implements the pairing.Suite interface for the Bls12381 bilinear pairing.
type Suite struct {
	*commonSuite
	g1 *groupG1
	g2 *groupG2
	gt *groupGT
}

// NewSuite generates and returns a new Bls12381 pairing suite.
func NewSuite() *Suite {
	s := &Suite{commonSuite: &commonSuite{}}
	s.g1 = &groupG1{commonSuite: s.commonSuite, common: common{isPrime: true}}
	s.g2 = &groupG2{commonSuite: s.commonSuite, common: common{isPrime: false}}
	s.gt = &groupGT{commonSuite: s.commonSuite, common: common{isPrime: false}}
	return s
}

// NewSuiteG1 returns a G1 suite.
func NewSuiteG1() *Suite {
	s := NewSuite()
	s.commonSuite.Group = &groupG1{commonSuite: &commonSuite{}, common: common{isPrime: true}}
	return s
}

// NewSuiteG2 returns a G2 suite.
func NewSuiteG2() *Suite {
	s := NewSuite()
	s.commonSuite.Group = &groupG2{commonSuite: &commonSuite{}, common: common{isPrime: true}}
	return s
}

// NewSuiteGT returns a GT suite.
func NewSuiteGT() *Suite {
	s := NewSuite()
	s.commonSuite.Group = &groupGT{commonSuite: &commonSuite{}, common: common{isPrime: true}}
	return s
}

// NewSuiteRand generates and returns a new BN256 suite seeded by the
// given cipher stream.
func NewSuiteRand(rand cipher.Stream) *Suite {
	s := &Suite{commonSuite: &commonSuite{s: rand}}
	s.g1 = &groupG1{commonSuite: s.commonSuite, common: common{isPrime: true}}
	s.g2 = &groupG2{commonSuite: s.commonSuite, common: common{isPrime: false}}
	s.gt = &groupGT{commonSuite: s.commonSuite, common: common{isPrime: false}}
	return s
}

// G1 returns the group G1 of the BN256 pairing.
func (s *Suite) G1() kyber.Group {
	return s.g1
}

// G2 returns the group G2 of the BN256 pairing.
func (s *Suite) G2() kyber.Group {
	return s.g2
}

// GT returns the group GT of the BN256 pairing.
func (s *Suite) GT() kyber.Group {
	return s.gt
}

func (s *Suite) ValidatePairing(p1, p2, p3, p4 kyber.Point) bool {
	e := bls12381.NewEngine()
	e.AddPair(p1.(*pointG1).p, p2.(*pointG2).p)
	e.AddPairInv(p3.(*pointG1).p, p4.(*pointG2).p)
	return e.Check()
}

func (s *Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	e := bls12381.NewEngine()
	g1point := p1.(*pointG1).p
	g2point := p2.(*pointG2).p
	return newPointGT(e.AddPair(g1point, g2point).Result())
}

// Not used other than for reflect.TypeOf()
var aScalar kyber.Scalar
var aPoint kyber.Point
var aPointG1 pointG1
var aPointG2 pointG2
var aPointGT pointGT

var tScalar = reflect.TypeOf(&aScalar).Elem()
var tPoint = reflect.TypeOf(&aPoint).Elem()
var tPointG1 = reflect.TypeOf(&aPointG1).Elem()
var tPointG2 = reflect.TypeOf(&aPointG2).Elem()
var tPointGT = reflect.TypeOf(&aPointGT).Elem()

type commonSuite struct {
	s cipher.Stream
	// kyber.Group is only set if we have a combined Suite
	kyber.Group
}

// New implements the kyber.Encoding interface.
func (c *commonSuite) New(t reflect.Type) interface{} {
	if c.Group == nil {
		panic("cannot create Point from NewGroup - please use bls12381.NewGroupG1")
	}
	switch t {
	case tScalar:
		return c.Scalar()
	case tPoint:
		return c.Point()
	case tPointG1:
		g1 := groupG1{}
		return g1.Point()
	case tPointG2:
		g2 := groupG2{}
		return g2.Point()
	case tPointGT:
		gt := groupGT{}
		return gt.Point()
	}
	return nil
}

// Read is the default implementation of kyber.Encoding interface Read.
func (c *commonSuite) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, c, objs...)
}

// Write is the default implementation of kyber.Encoding interface Write.
func (c *commonSuite) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// Hash returns a newly instantiated sha256 hash function.
func (c *commonSuite) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newlly instantiated blake2xb XOF function.
func (c *commonSuite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (c *commonSuite) RandomStream() cipher.Stream {
	if c.s != nil {
		return c.s
	}
	return random.New()
}

// String returns a recognizable string that this is a combined suite.
func (c commonSuite) String() string {
	if c.Group != nil {
		return c.Group.String()
	}
	return "bls12381"
}
