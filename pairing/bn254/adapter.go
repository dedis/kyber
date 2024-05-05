package bn254

import (
	"go.dedis.ch/kyber/v3"
)

// SuiteBn254 is an adapter that implements the suites.Suite interface so that
// bn254 can be used as a common suite to generate key pairs for instance but
// still preserves the properties of the pairing (e.g. the Pair function).
//
// It's important to note that the Point function will generate a point
// compatible with public keys only (group G2) where the signature must be
// used as a point from the group G1.
type SuiteBn254 struct {
	*Suite
	kyber.Group
}

// NewSuiteBn254 makes a new BN254 suite
func NewSuiteBn254() *SuiteBn254 {
	return &SuiteBn254{
		Suite: NewSuite(),
	}
}

// Point generates a point from the G2 group that can only be used
// for public keys
func (s *SuiteBn254) Point() kyber.Point {
	return s.G2().Point()
}

// PointLen returns the length of a G2 point
func (s *SuiteBn254) PointLen() int {
	return s.G2().PointLen()
}

// Scalar generates a scalar
func (s *SuiteBn254) Scalar() kyber.Scalar {
	return s.G1().Scalar()
}

// ScalarLen returns the lenght of a scalar
func (s *SuiteBn254) ScalarLen() int {
	return s.G1().ScalarLen()
}

// String returns the name of the suite
func (s *SuiteBn254) String() string {
	return "bn254.adapter"
}
