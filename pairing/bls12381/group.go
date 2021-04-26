package bls12381

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// GroupChecker allows to verify if a Point is in the correct group or not. For
// curves which don't have a prime order, we need to only consider the points
// lying in the subgroup of prime order. That check returns true if the point is
// correct or not.
type GroupChecker interface {
	kyber.Point
	IsInCorrectGroup() bool
}

type common struct {
	isPrime bool
}

func (g *common) Scalar() kyber.Scalar {
	return NewKyberScalar()
}

func (g *common) ScalarLen() int {
	return g.Scalar().MarshalSize()
}

func (g *common) IsPrimeOrder() bool {
	return g.isPrime
}

func (g *common) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newlly instantiated blake2xb XOF function.
func (g *common) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (g *common) RandomStream() cipher.Stream {
	return random.New()
}

type groupG1 struct {
	common
	*commonSuite
}

func (g *groupG1) String() string {
	return "bls12381.G1"
}

func (g *groupG1) Point() kyber.Point {
	return nullpointG1()
}

func (g *groupG1) PointLen() int {
	return g.Point().MarshalSize()
}

type groupG2 struct {
	common
	*commonSuite
}

func (g *groupG2) String() string {
	return "bls12381.G2"
}

func (g *groupG2) Point() kyber.Point {
	return nullpointG2()
}

func (g *groupG2) PointLen() int {
	return g.Point().MarshalSize()
}

type groupGT struct {
	common
	*commonSuite
}

func (g *groupGT) String() string {
	return "bls12381.GT"
}

func (g *groupGT) Point() kyber.Point {
	return newEmptyGT()
}

func (g *groupGT) PointLen() int {
	return g.Point().MarshalSize()
}

func newGroupG1() kyber.Group {
	return &groupG1{
		common: common{isPrime: true},
	}
}

func newGroupG2() kyber.Group {
	return &groupG2{
		common: common{isPrime: false},
	}
}
