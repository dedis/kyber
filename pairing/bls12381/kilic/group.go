package kilic

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

type groupBls struct {
	str      string
	newPoint func() kyber.Point
	isPrime  bool
}

func (g *groupBls) String() string {
	return g.str
}

func (g *groupBls) Scalar() kyber.Scalar {
	return NewScalar()
}

func (g *groupBls) ScalarLen() int {
	return g.Scalar().MarshalSize()
}

func (g *groupBls) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *groupBls) Point() kyber.Point {
	return g.newPoint()
}

func (g *groupBls) IsPrimeOrder() bool {
	return g.isPrime
}

func (g *groupBls) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newly instantiated blake2xb XOF function.
func (g *groupBls) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (g *groupBls) RandomStream() cipher.Stream {
	return random.New()
}

func NewGroupG1(dst ...byte) kyber.Group {
	return &groupBls{
		str:      "bls12-381.G1",
		newPoint: func() kyber.Point { return NullG1(dst...) },
		isPrime:  true,
	}
}

func NewGroupG2(dst ...byte) kyber.Group {
	return &groupBls{
		str:      "bls12-381.G2",
		newPoint: func() kyber.Point { return NullG2(dst...) },
		isPrime:  false,
	}
}

func NewGroupGT() kyber.Group {
	return &groupBls{
		str:      "bls12-381.GT",
		newPoint: func() kyber.Point { return newEmptyGT() },
		isPrime:  false,
	}
}
