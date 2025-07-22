//go:build !constantTime

package p256

import (
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
	"go.dedis.ch/kyber/v4/compatible"
	"io"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/compatible"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/util/random"
)

type curvePoint struct {
	x, y *compatible.Int
	c    *curve
}

func (P *curvePoint) String() string {
	return "(" + P.x.String() + "," + P.y.String() + ")"
}

func (P *curvePoint) Equal(P2 kyber.Point) bool {
	cp2 := P2.(*curvePoint) //nolint:errcheck // Design pattern to emulate generics

	// Make sure both coordinates are normalized.
	// Apparently Go's elliptic curve code doesn't always ensure this.
	M := P.c.p.P
	P.x.Mod(P.x, M)
	P.y.Mod(P.y, M)
	cp2.x.Mod(cp2.x, M)
	cp2.y.Mod(cp2.y, M)

	return P.x.Cmp(cp2.x) == 0 && P.y.Cmp(cp2.y) == 0
}

func (P *curvePoint) Null() kyber.Point {
	P.x = new(compatible.Int).SetUint64(0)
	P.y = new(compatible.Int).SetUint64(0)
	return P
}

func (P *curvePoint) Base() kyber.Point {
	P.x = P.c.p.Gx
	P.y = P.c.p.Gy
	return P
}

func (P *curvePoint) Valid() bool {
	// The IsOnCurve function in Go's elliptic curve package
	// doesn't consider the point-at-infinity to be "on the curve"
	return P.c.IsOnCurve(P.x, P.y) ||
		(P.x.Sign() == 0 && P.y.Sign() == 0)
}

// Try to generate a point on this curve from a chosen x-coordinate,
// with a random sign.
func (P *curvePoint) genPoint(x *compatible.Int, rand cipher.Stream) bool {
	// Compute the corresponding Y coordinate, if any
	y2 := new(compatible.Int).Mul(x, x)
	y2.Mul(y2, x)
	threeX := new(compatible.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	y2.Sub(y2, threeX)
	y2.Add(y2, P.c.p.B)
	y2.Mod(y2, P.c.p.P)
	y := P.c.sqrt(y2)

	// Pick a random sign for the y coordinate
	b := make([]byte, 1)
	rand.XORKeyStream(b, b)
	if (b[0] & 0x80) != 0 {
		y.Sub(P.c.p.P, y)
	}

	// Check that it's a valid point
	y2t := new(compatible.Int).Mul(y, y)
	y2t.Mod(y2t, P.c.p.P)
	if y2t.Cmp(y2) != 0 {
		return false // Doesn't yield a valid point!
	}

	P.x = x
	P.y = y
	return true
}

func (P *curvePoint) EmbedLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (P.c.p.P.BitLen() - 8 - 8) / 8
}

func (P *curvePoint) Pick(rand cipher.Stream) kyber.Point {
	return P.Embed(nil, rand)
}

// Embed picks a curve point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
func (P *curvePoint) Embed(data []byte, rand cipher.Stream) kyber.Point {
	l := P.c.coordLen()
	dl := P.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := random.Bits(uint(P.c.p.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)         // Encode length in low 8 bits
			copy(b[l-dl-1:l-1], data) // Copy in data to embed
		}
		if P.genPoint(new(compatible.Int).SetBytes(b), rand) {
			return P
		}
	}
}

// Data extracts embedded data from a curve point
func (P *curvePoint) Data() ([]byte, error) {
	b := P.x.Bytes()
	l := P.c.coordLen()
	if len(b) < l { // pad leading zero bytes if necessary
		b = append(make([]byte, l-len(b)), b...)
	}
	dl := int(b[l-1])
	if dl > P.EmbedLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[l-dl-1 : l-1], nil
}

func (P *curvePoint) Add(A, B kyber.Point) kyber.Point {
	ca := A.(*curvePoint) //nolint:errcheck // Design pattern to emulate generics
	cb := B.(*curvePoint) //nolint:errcheck // Design pattern to emulate generics
	P.x, P.y = P.c.Add(ca.x, ca.y, cb.x, cb.y)
	return P
}

func (P *curvePoint) Sub(A, B kyber.Point) kyber.Point {
	ca := A.(*curvePoint) //nolint:errcheck // Design pattern to emulate generics
	cb := B.(*curvePoint) //nolint:errcheck // Design pattern to emulate generics

	cbn := P.c.Point().Neg(cb).(*curvePoint) //nolint:errcheck // Design pattern to emulate generics
	P.x, P.y = P.c.Add(ca.x, ca.y, cbn.x, cbn.y)
	return P
}

func (P *curvePoint) Neg(A kyber.Point) kyber.Point {
	s := P.c.Scalar().One()
	s.Neg(s)
	return P.Mul(s, A).(*curvePoint)
}

func (P *curvePoint) Mul(s kyber.Scalar, B kyber.Point) kyber.Point {
	cs := s.(*mod.Int) //nolint:errcheck // Design pattern to emulate generics
	if B != nil {
		cb := B.(*curvePoint) //nolint:errcheck // Design pattern to emulate generics
		P.x, P.y = P.c.ScalarMult(cb.x, cb.y, cs.V.Bytes())
	} else {
		P.x, P.y = P.c.ScalarBaseMult(cs.V.Bytes())
	}
	return P
}

func (P *curvePoint) MarshalSize() int {
	coordlen := (P.c.Params().BitSize + 7) >> 3
	return 1 + 2*coordlen // uncompressed ANSI X9.62 representation
}

func (P *curvePoint) MarshalBinary() ([]byte, error) {
	return elliptic.Marshal(P.c, P.x, P.y), nil
}

func (P *curvePoint) UnmarshalBinary(buf []byte) error {
	// Check whether all bytes after first one are 0, so we
	// just return the initial point. Read everything to
	// prevent timing-leakage.
	var c byte
	for _, b := range buf[1:] {
		c |= b
	}
	if c != 0 {
		P.x, P.y = elliptic.Unmarshal(P.c, buf)
		if P.x == nil || !P.Valid() {
			return errors.New("invalid elliptic curve point")
		}
	} else {
		// All bytes are 0, so we initialize x and y
		P.x = compatible.NewInt(0)
		P.y = compatible.NewInt(0)
	}
	return nil
}

func (P *curvePoint) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(P, w)
}

func (P *curvePoint) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(P, r)
}

// interface for curve-specifc mathematical functions
type curveOps interface {
	sqrt(y *compatible.Int) *compatible.Int
}

// Curve is an implementation of the kyber.Group interface
// for NIST elliptic curves, built on Go's native elliptic curve library.
type curve struct {
	elliptic.Curve
	curveOps
	p *elliptic.CurveParams
}

// Return the number of bytes in the encoding of a Scalar for this curve.
func (c *curve) ScalarLen() int { return (c.p.N.BitLen() + 7) / 8 }

// Create a Scalar associated with this curve. The scalars created by
// this package implement kyber.Scalar's SetBytes method, interpreting
// the bytes as a big-endian integer, so as to be compatible with the
// Go standard library's big.Int type.
func (c *curve) Scalar() kyber.Scalar {
	return mod.NewInt64(0, c.p.N)
}

// Number of bytes required to store one coordinate on this curve
func (c *curve) coordLen() int {
	return (c.p.BitSize + 7) / 8
}

// Return the number of bytes in the encoding of a Point for this curve.
// Currently uses uncompressed ANSI X9.62 format with both X and Y coordinates;
// this could change.
func (c *curve) PointLen() int {
	return 1 + 2*c.coordLen() // ANSI X9.62: 1 header byte plus 2 coords
}

// Create a Point associated with this curve.
func (c *curve) Point() kyber.Point {
	p := new(curvePoint)
	p.c = c
	return p
}

func (P *curvePoint) Set(A kyber.Point) kyber.Point {
	P.x = A.(*curvePoint).x
	P.y = A.(*curvePoint).y
	return P
}

func (P *curvePoint) Clone() kyber.Point {
	return &curvePoint{x: P.x, y: P.y, c: P.c}
}

// Return the order of this curve: the prime N in the curve parameters.
func (c *curve) Order() *compatible.Int {
	return c.p.N
}
