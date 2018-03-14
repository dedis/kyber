package bn256

import (
	"crypto/cipher"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/mod"
)

type groupG1 struct {
	common
}

func (g *groupG1) String() string {
	return "bn256.G1"
}

func (g *groupG1) PointLen() int {
	return newPointG1().MarshalSize()
}

func (g *groupG1) Point() kyber.Point {
	return newPointG1()
}

type groupG2 struct {
	common
}

func (g *groupG2) String() string {
	return "bn256.G2"
}

func (g *groupG2) PointLen() int {
	return newPointG2().MarshalSize()
}

func (g *groupG2) Point() kyber.Point {
	return newPointG2()
}

type groupGT struct {
	common
}

func (g *groupGT) String() string {
	return "bn256.GT"
}

func (g *groupGT) PointLen() int {
	return newPointGT().MarshalSize()
}

func (g *groupGT) Point() kyber.Point {
	return newPointGT()
}

// common functionalities across G1, G2, and GT
type common struct{}

func (c *common) ScalarLen() int {
	return mod.NewInt64(0, Order).MarshalSize()
}

func (c *common) Scalar() kyber.Scalar {
	return mod.NewInt64(0, Order)
}

func (c *common) PrimeOrder() bool {
	return true
}

func (c *common) NewKey(rand cipher.Stream) kyber.Scalar {
	return mod.NewInt64(0, Order).Pick(rand)
}
