package ed25519

import (
	"crypto/cipher"

	"github.com/dedis/crypto/abstract"
)

type ed25519Point struct {
	*point
}

func newEd25519Point() *ed25519Point {
	return &ed25519Point{
		point: new(point),
	}
}
func (e *ed25519Point) Equal(P2 abstract.Point) bool {
	return e.point.Equal(castToPoint(P2))
}

func (e *ed25519Point) Null() abstract.Point {
	e.point.Null()
	return e
}

func (e *ed25519Point) Base() abstract.Point {
	e.point.Base()
	return e
}

func (e *ed25519Point) Pick(data []byte, rand cipher.Stream) (abstract.Point, []byte) {
	_, buff := e.point.Pick(data, rand)
	return e, buff
}

func (e *ed25519Point) PickLen() int {
	return e.point.PickLen()
}

func (e *ed25519Point) Data() ([]byte, error) {
	return e.point.Data()
}
func (e *ed25519Point) Add(P1, P2 abstract.Point) abstract.Point {
	e.point.Add(castToPoint(P1), castToPoint(P2))
	return e
}

func (e *ed25519Point) Sub(P1, P2 abstract.Point) abstract.Point {
	e.point.Sub(castToPoint(P1), castToPoint(P2))
	return e
}
func (e *ed25519Point) Neg(P1 abstract.Point) abstract.Point {
	e.point.Neg(castToPoint(P1))
	return e
}

func (e *ed25519Point) Mul(A abstract.Point, s abstract.Secret) abstract.Point {
	sb, _ := s.MarshalBinary()
	var a [32]byte
	copy(a[:], sb)

	if A == nil {
		geScalarMultBase(&e.ge, &a)
	} else {
		geScalarMult(&e.ge, &a, &A.(*ed25519Point).ge)
	}
	return e
}

func (e *ed25519Point) Set(P2 abstract.Point) abstract.Point {
	e.point.Set(castToPoint(P2))
	return e
}

func castToPoint(p abstract.Point) *point {
	return p.(*ed25519Point).point
}
