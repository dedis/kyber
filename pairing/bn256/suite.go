package bn256

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/fixbuf"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/mod"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof/blake2xb"
)

// Suite implements the pairing.Suite interface for the BN256 bilinear pairing.
type Suite struct {
	g1 *groupG1
	g2 *groupG2
	gt *groupGT
	r  cipher.Stream
}

// NewSuite generates and returns a new BN256 pairing suite.
func NewSuite() *Suite {
	s := &Suite{}
	s.g1 = &groupG1{}
	s.g2 = &groupG2{}
	s.gt = &groupGT{}
	return s
}

// NewSuiteRand generates and returns a new BN256 suite seeded by the
// given cipher stream.
func NewSuiteRand(rand cipher.Stream) *Suite {
	s := &Suite{}
	s.g1 = &groupG1{}
	s.g2 = &groupG2{}
	s.gt = &groupGT{}
	s.r = rand
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

// Pair takes the points p1 and p2 in groups G1 and G2, respectively, as input
// and computes their pairing in GT.
func (s *Suite) Pair(p1 kyber.Point, p2 kyber.Point) kyber.Point {
	return s.GT().Point().(*pointGT).Pair(p1, p2)
}

// Hash returns a newly instantiated sha256 hash function.
func (s *Suite) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newlly instantiated blake2xb XOF function.
func (s *Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (s *Suite) RandomStream() cipher.Stream {
	if s.r != nil {
		return s.r
	}
	return random.New()
}

// Read is the default implementation of kyber.Encoding interface Read.
func (s *Suite) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs...)
}

// Write is the default implementation of kyber.Encoding interface Write.
func (s *Suite) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

// Not used other than for reflect.TypeOf()
var aScalar mod.Int
var aPointG1 pointG1
var aPointG2 pointG2
var aPointGT pointGT

var tScalar = reflect.TypeOf(&aScalar).Elem()
var tPointG1 = reflect.TypeOf(&aPointG1).Elem()
var tPointG2 = reflect.TypeOf(&aPointG2).Elem()
var tPointGT = reflect.TypeOf(&aPointGT).Elem()

// New implements the kyber.Encoding interface.
func (s *Suite) New(t reflect.Type) interface{} {
	switch t {
	case tScalar:
		return s.G1().Scalar()
	case tPointG1:
		return s.G1().Point()
	case tPointG2:
		return s.G2().Point()
	case tPointGT:
		return s.GT().Point()
	}
	return nil
}
