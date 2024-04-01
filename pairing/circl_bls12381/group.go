package circl_bls12381

import (
	circl "github.com/cloudflare/circl/ecc/bls12381"
	"go.dedis.ch/kyber/v3"
)

var (
	G1 kyber.Group = &groupBls{name: "bls12-381.G1", newPoint: func() kyber.Point { return new(G1Elt).Null() }}
	G2 kyber.Group = &groupBls{name: "bls12-381.G2", newPoint: func() kyber.Point { return new(G2Elt).Null() }}
	GT kyber.Group = &groupBls{name: "bls12-381.GT", newPoint: func() kyber.Point { return new(GTElt).Null() }}
)

type groupBls struct {
	name     string
	newPoint func() kyber.Point
}

func (g groupBls) String() string       { return g.name }
func (g groupBls) ScalarLen() int       { return circl.ScalarSize }
func (g groupBls) Scalar() kyber.Scalar { return new(Scalar).SetInt64(0) }
func (g groupBls) PointLen() int        { return g.newPoint().MarshalSize() }
func (g groupBls) Point() kyber.Point   { return g.newPoint() }
