package pairing

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
)

// SuiteBn256 is an adapter from the different bn256 suites to a single one
// that can be used by onet to encode/decode key pairs. The public key comes
// from the field G2 and the private key comes from G1 thus the Point and
// Scalar functions return the corresponding type.
type SuiteBn256 struct {
	Suite
	kyber.Group
}

// NewSuiteBn256 makes a new BN256 suite
func NewSuiteBn256() *SuiteBn256 {
	return &SuiteBn256{
		Suite: bn256.NewSuite(),
	}
}

// Point returns a new point from the G2 field
func (s *SuiteBn256) Point() kyber.Point {
	return s.G2().Point()
}

// PointLen returns the length of a G2 point
func (s *SuiteBn256) PointLen() int {
	return s.G2().PointLen()
}

// Scalar returns the scalar of the G1 field
func (s *SuiteBn256) Scalar() kyber.Scalar {
	return s.G1().Scalar()
}

// ScalarLen returns the lenght of a scalar of the G1 field
func (s *SuiteBn256) ScalarLen() int {
	return s.G1().ScalarLen()
}

// String returns the name of the suite
func (s *SuiteBn256) String() string {
	return "bn256.adapter"
}
