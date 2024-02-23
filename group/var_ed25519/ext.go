package var_ed25519

import (
	"crypto/cipher"
	"encoding/hex"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"go.dedis.ch/kyber/v4/group/mod"
)

type extPoint struct {
	X, Y, Z, T mod.Int
	c          *ExtendedCurve
}

func (p *extPoint) initXY(x, y *big.Int, c kyber.Group) {
	var ok bool
	p.c, ok = c.(*ExtendedCurve)
	if !ok {
		panic("invalid casting to *ExtendedCurve")
	}

	p.X.Init(x, &p.c.P)
	p.Y.Init(y, &p.c.P)
	p.Z.Init64(1, &p.c.P)
	p.T.Mul(&p.X, &p.Y)
}

func (p *extPoint) getXY() (x, y *mod.Int) {
	p.normalize()
	return &p.X, &p.Y
}

func (p *extPoint) String() string {
	p.normalize()
	buf, _ := p.MarshalBinary()
	return hex.EncodeToString(buf)
}

func (p *extPoint) MarshalSize() int {
	return p.c.PointLen()
}

func (p *extPoint) MarshalBinary() ([]byte, error) {
	p.normalize()
	return p.c.encodePoint(&p.X, &p.Y), nil
}

func (p *extPoint) UnmarshalBinary(b []byte) error {
	if err := p.c.decodePoint(b, &p.X, &p.Y); err != nil {
		return err
	}
	p.Z.Init64(1, &p.c.P)
	p.T.Mul(&p.X, &p.Y)
	return nil
}

func (p *extPoint) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(p, w)
}

func (p *extPoint) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}

// Equality test for two Points on the same curve.
// We can avoid inversions here because:
//
//	(X1/Z1,Y1/Z1) == (X2/Z2,Y2/Z2)
//		iff
//	(X1*Z2,Y1*Z2) == (X2*Z1,Y2*Z1)
func (p *extPoint) Equal(cp2 kyber.Point) bool {
	p2, ok := cp2.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	var t1, t2 mod.Int
	xeq := t1.Mul(&p.X, &p2.Z).Equal(t2.Mul(&p2.X, &p.Z))
	yeq := t1.Mul(&p.Y, &p2.Z).Equal(t2.Mul(&p2.Y, &p.Z))
	return xeq && yeq
}

func (p *extPoint) Set(cp2 kyber.Point) kyber.Point {
	p2, ok := cp2.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	p.c = p2.c
	p.X.Set(&p2.X)
	p.Y.Set(&p2.Y)
	p.Z.Set(&p2.Z)
	p.T.Set(&p2.T)
	return p
}

func (p *extPoint) Clone() kyber.Point {
	p2 := extPoint{}
	p2.c = p.c
	p2.X.Set(&p.X)
	p2.Y.Set(&p.Y)
	p2.Z.Set(&p.Z)
	p2.T.Set(&p.T)
	return &p2
}

func (p *extPoint) Null() kyber.Point {
	p.Set(&p.c.null)
	return p
}

func (p *extPoint) Base() kyber.Point {
	p.Set(&p.c.base)
	return p
}

func (p *extPoint) EmbedLen() int {
	return p.c.embedLen()
}

// Normalize the point's representation to Z=1.
func (p *extPoint) normalize() {
	p.Z.Inv(&p.Z)
	p.X.Mul(&p.X, &p.Z)
	p.Y.Mul(&p.Y, &p.Z)
	p.Z.V.SetInt64(1)
	p.T.Mul(&p.X, &p.Y)
}

// Check the validity of the T coordinate
func (p *extPoint) checkT() {
	var t1, t2 mod.Int
	if !t1.Mul(&p.X, &p.Y).Equal(t2.Mul(&p.Z, &p.T)) {
		panic("oops")
	}
}

func (p *extPoint) Embed(data []byte, rand cipher.Stream) kyber.Point {
	p.c.embed(p, data, rand)
	return p
}

func (p *extPoint) Pick(rand cipher.Stream) kyber.Point {
	p.c.embed(p, nil, rand)
	return p
}

// Extract embedded data from a point group element
func (p *extPoint) Data() ([]byte, error) {
	p.normalize()
	return p.c.data(&p.X, &p.Y)
}

// Add two points using optimized extended coordinate addition formulas.
//
//nolint:dupl //Doesn't make sense to extract part of Add(), Sub(), double()
func (p *extPoint) Add(cp1, cp2 kyber.Point) kyber.Point {
	p1, ok := cp1.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	p2, ok := cp2.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	X1, Y1, Z1, T1 := &p1.X, &p1.Y, &p1.Z, &p1.T
	X2, Y2, Z2, T2 := &p2.X, &p2.Y, &p2.Z, &p2.T
	X3, Y3, Z3, T3 := &p.X, &p.Y, &p.Z, &p.T
	var A, B, C, D, E, F, G, H mod.Int

	A.Mul(X1, X2)
	B.Mul(Y1, Y2)
	C.Mul(T1, T2).Mul(&C, &p.c.d)
	D.Mul(Z1, Z2)
	E.Add(X1, Y1).Mul(&E, F.Add(X2, Y2)).Sub(&E, &A).Sub(&E, &B)
	F.Sub(&D, &C)
	G.Add(&D, &C)
	H.Mul(&p.c.a, &A).Sub(&B, &H)
	X3.Mul(&E, &F)
	Y3.Mul(&G, &H)
	T3.Mul(&E, &H)
	Z3.Mul(&F, &G)
	return p
}

// Subtract points.
//
//nolint:dupl //Doesn't make sense to extract part of Add(), Sub(), double()
func (p *extPoint) Sub(cp1, cp2 kyber.Point) kyber.Point {
	p1, ok := cp1.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	p2, ok := cp2.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	X1, Y1, Z1, T1 := &p1.X, &p1.Y, &p1.Z, &p1.T
	X2, Y2, Z2, T2 := &p2.X, &p2.Y, &p2.Z, &p2.T
	X3, Y3, Z3, T3 := &p.X, &p.Y, &p.Z, &p.T
	var A, B, C, D, E, F, G, H mod.Int

	A.Mul(X1, X2)
	B.Mul(Y1, Y2)
	C.Mul(T1, T2).Mul(&C, &p.c.d)
	D.Mul(Z1, Z2)
	E.Add(X1, Y1).Mul(&E, F.Sub(Y2, X2)).Add(&E, &A).Sub(&E, &B)
	F.Add(&D, &C)
	G.Sub(&D, &C)
	H.Mul(&p.c.a, &A).Add(&B, &H)
	X3.Mul(&E, &F)
	Y3.Mul(&G, &H)
	T3.Mul(&E, &H)
	Z3.Mul(&F, &G)
	return p
}

// Find the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (p *extPoint) Neg(ca kyber.Point) kyber.Point {
	A, ok := ca.(*extPoint)
	if !ok {
		panic("invalid casting to *extPoint")
	}
	p.c = A.c
	p.X.Neg(&A.X)
	p.Y.Set(&A.Y)
	p.Z.Set(&A.Z)
	p.T.Neg(&A.T)
	return p
}

// Optimized point doubling for use in scalar multiplication.
// Uses the formulae in section 3.3 of:
// https://www.iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
func (p *extPoint) double() {
	X1, Y1, Z1, T1 := &p.X, &p.Y, &p.Z, &p.T
	var A, B, C, D, E, F, G, H mod.Int

	A.Mul(X1, X1)
	B.Mul(Y1, Y1)
	C.Mul(Z1, Z1).Add(&C, &C)
	D.Mul(&p.c.a, &A)
	E.Add(X1, Y1).Mul(&E, &E).Sub(&E, &A).Sub(&E, &B)
	G.Add(&D, &B)
	F.Sub(&G, &C)
	H.Sub(&D, &B)
	X1.Mul(&E, &F)
	Y1.Mul(&G, &H)
	T1.Mul(&E, &H)
	Z1.Mul(&F, &G)
}

// Multiply point p by scalar s using the repeated doubling method.
//
// Currently doesn't implement the optimization of
// switching between projective and extended coordinates during
// scalar multiplication.
func (p *extPoint) Mul(s kyber.Scalar, g kyber.Point) kyber.Point {
	v := s.(*mod.Int).V
	if g == nil {
		return p.Base().Mul(s, p)
	}
	T := p
	if g == p { // Must use temporary for in-place multiply
		T = &extPoint{}
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

// ExtendedCurve implements Twisted Edwards curves
// using projective coordinate representation (X:Y:Z),
// satisfying the identities x = X/Z, y = Y/Z.
// This representation still supports all Twisted Edwards curves
// and avoids expensive modular inversions on the critical paths.
// Uses the projective arithmetic formulas in:
// http://cr.yp.to/newelliptic/newelliptic-20070906.pdf
//

// ExtendedCurve implements Twisted Edwards curves
// using the Extended Coordinate representation specified in:
// Hisil et al, "Twisted Edwards Curves Revisited",
// http://eprint.iacr.org/2008/522
//
// This implementation is designed to work with all Twisted Edwards curves,
// foregoing the further optimizations that are available for the
// special case with curve parameter a=-1.
// We leave the task of hyperoptimization to curve-specific implementations
// such as the ed25519 package.
type ExtendedCurve struct {
	curve          // generic Edwards curve functionality
	null  extPoint // Constant identity/null point (0,1)
	base  extPoint // Standard base point
}

// Point creates a new Point on this curve.
func (c *ExtendedCurve) Point() kyber.Point {
	P := new(extPoint)
	P.c = c
	//P.Set(&c.null)
	return P
}

// Init initializes the curve with given parameters.
func (c *ExtendedCurve) Init(p *Param, fullGroup bool) *ExtendedCurve {
	c.curve.init(c, p, fullGroup, &c.null, &c.base)
	return c
}
