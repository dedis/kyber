package nist

import (
	"errors"
	"io"
	"math/big"
	//"encoding/hex"
	"crypto/cipher"
	"crypto/elliptic"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/random"
)

type curvePoint struct {
	x, y  *big.Int
	c     *curve
	Suite string
}

func (cp *curvePoint) GetSuite() abstract.Suite {
	s, _ := abstract.StringToSuite(cp.Suite)
	return s
}

func (cp *curvePoint) SetSuite(s abstract.Suite) {
	cp.Suite = s.String()
}

// Point creates a Point-structure from a PointInterface
func (cp *curvePoint) Point() *abstract.Point {
	return &abstract.Point{cp}
}

func (p *curvePoint) String() string {
	return "(" + p.x.String() + "," + p.y.String() + ")"
}

func (p *curvePoint) Equal(p2 *abstract.Point) bool {
	cp2 := p2.PointInterface.(*curvePoint)

	// Make sure both coordinates are normalized.
	// Apparently Go's elliptic curve code doesn't always ensure this.
	M := p.c.p.P
	p.x.Mod(p.x, M)
	p.y.Mod(p.y, M)
	cp2.x.Mod(cp2.x, M)
	cp2.y.Mod(cp2.y, M)

	return p.x.Cmp(cp2.x) == 0 && p.y.Cmp(cp2.y) == 0
}

func (p *curvePoint) Null() *abstract.Point {
	p.x = new(big.Int).SetInt64(0)
	p.y = new(big.Int).SetInt64(0)
	return p.Point()
}

func (p *curvePoint) Base() *abstract.Point {
	p.x = p.c.p.Gx
	p.y = p.c.p.Gy
	return p.Point()
}

func (p *curvePoint) Valid() bool {
	// return p.c.IsOnCurve(p.x, p.y)

	// The IsOnCurve function in Go's elliptic curve package
	// doesn't consider the point-at-infinity to be "on the curve"
	return p.c.IsOnCurve(p.x, p.y) ||
		(p.x.Sign() == 0 && p.y.Sign() == 0)
}

// Try to generate a point on this curve from a chosen x-coordinate,
// with a random sign.
func (p *curvePoint) genPoint(x *big.Int, rand cipher.Stream) bool {

	// Compute the corresponding Y coordinate, if any
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	y2.Sub(y2, threeX)
	y2.Add(y2, p.c.p.B)
	y2.Mod(y2, p.c.p.P)
	y := p.c.sqrt(y2)

	// Pick a random sign for the y coordinate
	b := make([]byte, 1)
	rand.XORKeyStream(b, b)
	if (b[0] & 0x80) != 0 {
		y.Sub(p.c.p.P, y)
	}

	// Check that it's a valid point
	y2t := new(big.Int).Mul(y, y)
	y2t.Mod(y2t, p.c.p.P)
	if y2t.Cmp(y2) != 0 {
		return false // Doesn't yield a valid point!
	}

	p.x = x
	p.y = y
	return true
}

func (p *curvePoint) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (p.c.p.P.BitLen() - 8 - 8) / 8
}

// Pick a curve point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
func (p *curvePoint) Pick(data []byte, rand cipher.Stream) (*abstract.Point, []byte) {

	l := p.c.coordLen()
	dl := p.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := random.Bits(uint(p.c.p.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)         // Encode length in low 8 bits
			copy(b[l-dl-1:l-1], data) // Copy in data to embed
		}
		if p.genPoint(new(big.Int).SetBytes(b), rand) {
			return p.Point(), data[dl:]
		}
	}
}

// Extract embedded data from a curve point
func (p *curvePoint) Data() ([]byte, error) {
	b := p.x.Bytes()
	l := p.c.coordLen()
	if len(b) < l { // pad leading zero bytes if necessary
		b = append(make([]byte, l-len(b)), b...)
	}
	dl := int(b[l-1])
	if dl > p.PickLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[l-dl-1 : l-1], nil
}

func (p *curvePoint) Add(a, b *abstract.Point) *abstract.Point {
	ca := a.PointInterface.(*curvePoint)
	cb := b.PointInterface.(*curvePoint)
	p.x, p.y = p.c.Add(ca.x, ca.y, cb.x, cb.y)
	return p.Point()
}

func (p *curvePoint) Sub(a, b *abstract.Point) *abstract.Point {
	ca := a.PointInterface.(*curvePoint)

	// XXX a pretty non-optimal implementation of point subtraction...
	cbn := p.c.Point().Neg(b).PointInterface.(*curvePoint)
	p.x, p.y = p.c.Add(ca.x, ca.y, cbn.x, cbn.y)
	return p.Point()
}

func (p *curvePoint) Neg(a *abstract.Point) *abstract.Point {

	// XXX a pretty non-optimal implementation of point negation...
	s := p.c.Secret().One()
	s.Neg(s)
	return p.Mul(a, s)
}

func (p *curvePoint) Mul(b *abstract.Point, s *abstract.Secret) *abstract.Point {
	cs := s.SecretInterface.(*Int)
	if b != nil {
		cb := b.PointInterface.(*curvePoint)
		p.x, p.y = p.c.ScalarMult(cb.x, cb.y, cs.V.Bytes())
	} else {
		p.x, p.y = p.c.ScalarBaseMult(cs.V.Bytes())
	}
	return p.Point()
}

func (p *curvePoint) MarshalSize() int {
	coordlen := (p.c.Params().BitSize + 7) >> 3
	return 1 + 2*coordlen // uncompressed ANSI X9.62 representation (XXX)
}

func (p *curvePoint) MarshalBinary() ([]byte, error) {
	return elliptic.Marshal(p.c, p.x, p.y), nil
}

func (p *curvePoint) UnmarshalBinary(buf []byte) error {
	// Check whether all bytes after first one are 0, so we
	// just return the initial point. Read everything to
	// prevent timing-leakage.
	var c byte = 0
	for _, b := range buf[1:] {
		c |= b
	}
	if c != 0 {
		p.x, p.y = elliptic.Unmarshal(p.c, buf)
		if p.x == nil || !p.Valid() {
			return errors.New("invalid elliptic curve point")
		}
	} else {
		// All bytes are 0, so we initialize x and y
		p.x = big.NewInt(0)
		p.y = big.NewInt(0)
	}
	return nil
}

func (p *curvePoint) MarshalTo(w io.Writer) (int, error) {
	return group.PointMarshalTo(p.Point(), w)
}

func (p *curvePoint) UnmarshalFrom(r io.Reader) (int, error) {
	return group.PointUnmarshalFrom(p.Point(), r)
}

// interface for curve-specifc mathematical functions
type curveOps interface {
	sqrt(y *big.Int) *big.Int
}

// Curve is an implementation of the abstract Group interface
// for NIST elliptic curves, built on Go's native elliptic curve library.
type curve struct {
	elliptic.Curve
	curveOps
	p    *elliptic.CurveParams
	name string
}

// All the NIST curves we support are prime-order.
func (g *curve) PrimeOrder() bool {
	return true
}

// Return the number of bytes in the encoding of a Secret for this curve.
func (c *curve) SecretLen() int { return (c.p.N.BitLen() + 7) / 8 }

// Create a Secret associated with this curve.
func (c *curve) Secret() *abstract.Secret {
	s := NewInt(0, c.p.N)
	s.Suite = c.name
	return s.Secret()
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
func (c *curve) Point() *abstract.Point {
	p := new(curvePoint)
	p.c = c
	p.Suite = c.name
	return p.Point()
}

// Return the order of this curve: the prime N in the curve parameters.
func (c *curve) Order() *big.Int {
	return c.p.N
}
