package curve25519

import (
	"crypto/cipher"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/internal/marshalling"
	"go.dedis.ch/kyber/v3/group/mod"
)

type projPoint struct {
	X, Y, Z mod.Int
	c       *ProjectiveCurve
}

func (p *projPoint) initXY(x, y *big.Int, c kyber.Group) {
	p.c = c.(*ProjectiveCurve) //nolint:errcheck // V4 may bring better error handling
	p.X.Init(x, &p.c.P)
	p.Y.Init(y, &p.c.P)
	p.Z.Init64(1, &p.c.P)
}

func (p *projPoint) getXY() (x, y *mod.Int) {
	p.normalize()
	return &p.X, &p.Y
}

func (p *projPoint) String() string {
	p.normalize()
	return p.c.pointString(&p.X, &p.Y)
}

func (p *projPoint) MarshalSize() int {
	return p.c.PointLen()
}

func (p *projPoint) MarshalBinary() ([]byte, error) {
	p.normalize()
	return p.c.encodePoint(&p.X, &p.Y), nil
}

func (p *projPoint) UnmarshalBinary(b []byte) error {
	p.Z.Init64(1, &p.c.P)
	return p.c.decodePoint(b, &p.X, &p.Y)
}

func (p *projPoint) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(p, w)
}

func (p *projPoint) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}

// Equality test for two Points on the same curve.
// We can avoid inversions here because:
//
//	(X1/Z1,Y1/Z1) == (X2/Z2,Y2/Z2)
//		iff
//	(X1*Z2,Y1*Z2) == (X2*Z1,Y2*Z1)
func (p *projPoint) Equal(cp2 kyber.Point) bool {
	P2 := cp2.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	var t1, t2 mod.Int
	xeq := t1.Mul(&p.X, &P2.Z).Equal(t2.Mul(&P2.X, &p.Z))
	yeq := t1.Mul(&p.Y, &P2.Z).Equal(t2.Mul(&P2.Y, &p.Z))
	return xeq && yeq
}

func (p *projPoint) Set(cp2 kyber.Point) kyber.Point {
	P2 := cp2.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	p.c = P2.c
	p.X.Set(&P2.X)
	p.Y.Set(&P2.Y)
	p.Z.Set(&P2.Z)
	return p
}

func (p *projPoint) Clone() kyber.Point {
	P2 := projPoint{}
	P2.c = p.c
	P2.X.Set(&p.X)
	P2.Y.Set(&p.Y)
	P2.Z.Set(&p.Z)
	return &P2
}

func (p *projPoint) Null() kyber.Point {
	p.Set(&p.c.null)
	return p
}

func (p *projPoint) Base() kyber.Point {
	p.Set(&p.c.base)
	return p
}

func (p *projPoint) EmbedLen() int {
	return p.c.embedLen()
}

// Normalize the point's representation to Z=1.
func (p *projPoint) normalize() {
	p.Z.Inv(&p.Z)
	p.X.Mul(&p.X, &p.Z)
	p.Y.Mul(&p.Y, &p.Z)
	p.Z.V.SetInt64(1)
}

func (p *projPoint) Embed(data []byte, rand cipher.Stream) kyber.Point {
	p.c.embed(p, data, rand)
	return p
}

func (p *projPoint) Pick(rand cipher.Stream) kyber.Point {
	return p.Embed(nil, rand)
}

// Extract embedded data from a point group element
func (p *projPoint) Data() ([]byte, error) {
	p.normalize()
	return p.c.data(&p.X, &p.Y)
}

// Add two points using optimized projective coordinate addition formulas.
// Formulas taken from:
//
//	http://eprint.iacr.org/2008/013.pdf
//	https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
//
//nolint:dupl //Doesn't make sense to extract part of Add(), Sub()
func (p *projPoint) Add(cp1, cp2 kyber.Point) kyber.Point {
	P1 := cp1.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	P2 := cp2.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	X1, Y1, Z1 := &P1.X, &P1.Y, &P1.Z
	X2, Y2, Z2 := &P2.X, &P2.Y, &P2.Z
	var A, B, C, D, E, F, G, X3, Y3, Z3 mod.Int

	A.Mul(Z1, Z2)
	B.Mul(&A, &A)
	C.Mul(X1, X2)
	D.Mul(Y1, Y2)
	E.Mul(&C, &D).Mul(&p.c.d, &E)
	F.Sub(&B, &E)
	G.Add(&B, &E)
	X3.Add(X1, Y1).Mul(&X3, Z3.Add(X2, Y2)).Sub(&X3, &C).Sub(&X3, &D).
		Mul(&F, &X3).Mul(&A, &X3)
	Y3.Mul(&p.c.a, &C).Sub(&D, &Y3).Mul(&G, &Y3).Mul(&A, &Y3)
	Z3.Mul(&F, &G)

	p.c = P1.c
	p.X.Set(&X3)
	p.Y.Set(&Y3)
	p.Z.Set(&Z3)
	return p
}

// Subtract points so that their scalars subtract homomorphically
//
//nolint:dupl //Doesn't make sense to extract part of Add(), Sub(), double()
func (p *projPoint) Sub(cp1, cp2 kyber.Point) kyber.Point {
	P1 := cp1.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	P2 := cp2.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	X1, Y1, Z1 := &P1.X, &P1.Y, &P1.Z
	X2, Y2, Z2 := &P2.X, &P2.Y, &P2.Z
	var A, B, C, D, E, F, G, X3, Y3, Z3 mod.Int

	A.Mul(Z1, Z2)
	B.Mul(&A, &A)
	C.Mul(X1, X2)
	D.Mul(Y1, Y2)
	E.Mul(&C, &D).Mul(&p.c.d, &E)
	F.Add(&B, &E)
	G.Sub(&B, &E)
	X3.Add(X1, Y1).Mul(&X3, Z3.Sub(Y2, X2)).Add(&X3, &C).Sub(&X3, &D).
		Mul(&F, &X3).Mul(&A, &X3)
	Y3.Mul(&p.c.a, &C).Add(&D, &Y3).Mul(&G, &Y3).Mul(&A, &Y3)
	Z3.Mul(&F, &G)

	p.c = P1.c
	p.X.Set(&X3)
	p.Y.Set(&Y3)
	p.Z.Set(&Z3)
	return p
}

// Find the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (p *projPoint) Neg(ca kyber.Point) kyber.Point {
	A := ca.(*projPoint) //nolint:errcheck // V4 may bring better error handling
	p.c = A.c
	p.X.Neg(&A.X)
	p.Y.Set(&A.Y)
	p.Z.Set(&A.Z)
	return p
}

// Optimized point doubling for use in scalar multiplication.
func (p *projPoint) double() {
	var B, C, D, E, F, H, J mod.Int

	B.Add(&p.X, &p.Y).Mul(&B, &B)
	C.Mul(&p.X, &p.X)
	D.Mul(&p.Y, &p.Y)
	E.Mul(&p.c.a, &C)
	F.Add(&E, &D)
	H.Mul(&p.Z, &p.Z)
	J.Add(&H, &H).Sub(&F, &J)
	p.X.Sub(&B, &C).Sub(&p.X, &D).Mul(&p.X, &J)
	p.Y.Sub(&E, &D).Mul(&F, &p.Y)
	p.Z.Mul(&F, &J)
}

// Multiply point p by scalar s using the repeated doubling method.
func (p *projPoint) Mul(s kyber.Scalar, g kyber.Point) kyber.Point {
	v := s.(*mod.Int).V
	if g == nil {
		return p.Base().Mul(s, p)
	}
	T := p
	if g == p { // Must use temporary for in-place multiply
		T = &projPoint{}
	}
	T.Set(&p.c.null) // Initialize to identity element (0,1)
	for i := v.BitLen() - 1; i >= 0; i-- {
		T.double()
		if v.Bit(i) != 0 {
			T.Add(T, g)
		}
	}
	if T != p {
		p.Set(T)
	}
	return p
}

// ProjectiveCurve implements Twisted Edwards curves
// using projective coordinate representation (X:Y:Z),
// satisfying the identities x = X/Z, y = Y/Z.
// This representation still supports all Twisted Edwards curves
// and avoids expensive modular inversions on the critical paths.
// Uses the projective arithmetic formulas in:
// http://cr.yp.to/newelliptic/newelliptic-20070906.pdf
type ProjectiveCurve struct {
	curve           // generic Edwards curve functionality
	null  projPoint // Constant identity/null point (0,1)
	base  projPoint // Standard base point
}

// Point creates a new Point on this curve.
func (c *ProjectiveCurve) Point() kyber.Point {
	P := new(projPoint)
	P.c = c

	return P
}

// Init initializes the curve with given parameters.
func (c *ProjectiveCurve) Init(p *Param, fullGroup bool) *ProjectiveCurve {
	c.curve.init(c, p, fullGroup, &c.null, &c.base)
	return c
}
