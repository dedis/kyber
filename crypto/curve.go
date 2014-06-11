package crypto

import (
	"errors"
	"math/big"
	"crypto/cipher"
	"crypto/elliptic"
)


type CurveSecret struct {
	big.Int 
	c *Curve
}

func (s *CurveSecret) String() string { return s.Int.String() }
func (s *CurveSecret) Equal(s2 Secret) bool {
	return s.Int.Cmp(&s2.(*CurveSecret).Int) == 0
}
func (s *CurveSecret) Encode() []byte { return s.Bytes() }
func (s *CurveSecret) Decode(buf []byte) Secret {
	s.SetBytes(buf)
	return s
}

type CurvePoint struct {
	x,y *big.Int 
	c *Curve
}

func (p *CurvePoint) String() string {
	return "("+p.x.String()+","+p.y.String()+")"
}
func (p *CurvePoint) Equal(p2 Point) bool {
	return	p.x.Cmp(p2.(*CurvePoint).x) == 0 &&
		p.y.Cmp(p2.(*CurvePoint).y) == 0
}
func (p *CurvePoint) Encode() []byte {
	return elliptic.Marshal(p.c, p.x, p.y)
}
func (p *CurvePoint) Decode(buf []byte) Point {
	p.x,p.y = elliptic.Unmarshal(p.c, buf)
	return p
}


// interface for curve-specifc mathematical functions
type curveOps interface {
	sqrt(y *big.Int) *big.Int
}

type Curve struct {
	elliptic.Curve
	curveOps
	p *elliptic.CurveParams
}


func (c *Curve) SecretLen() int { return (c.p.N.BitLen()+7)/8 }

func (c *Curve) RandomSecret(rand cipher.Stream) Secret {
	s := new(CurveSecret)
	s.c = c
	s.Int.Set(BigIntMod(c.p.N,rand))
	return s
}

func (c *Curve) AddSecret(x, y Secret) Secret {
	s := new(CurveSecret)
	s.c = c
	s.Int.Add(&x.(*CurveSecret).Int,&y.(*CurveSecret).Int)
	s.Int.Mod(&s.Int, c.p.N)
	return s
}


func (c *Curve) PointLen() int {
	coordlen := (c.p.BitSize+7)/8
	return 1+2*coordlen	// ANSI X9.62: 1 header byte plus 2 coords
}

func (c *Curve) IdentityPoint() Point {
	p := new(CurvePoint)
	p.c = c
	// x,y = 0 are the point at infinity
	return p
}

func (c *Curve) BasePoint() Point {
	p := new(CurvePoint)
	p.c = c
	p.x = c.p.Gx
	p.y = c.p.Gy
	return p
}

func (c *Curve) ValidPoint(p Point) bool {
	cp := p.(*CurvePoint)
	return c.IsOnCurve(cp.x,cp.y)
}

func (c *Curve) RandomPoint(rand cipher.Stream) Point {
	p := new(CurvePoint)
	p.c = c
	for {
		// Pick a random y coordinate with the correct modulus
		p.x = BigIntMod(c.p.P, rand)

		// Compute the corresponding Y coordinate, if any
		y2 := new(big.Int).Mul(p.x, p.x)
		y2.Mul(y2, p.x)
		threeX := new(big.Int).Lsh(p.x, 1)
		threeX.Add(threeX, p.x)
		y2.Sub(y2, threeX)
		y2.Add(y2, c.p.B)
		y2.Mod(y2, c.p.P)
		p.y = c.sqrt(y2)

		// Pick a random sign for the y coordinate
		b := make([]byte,1)
		rand.XORKeyStream(b,b)
		if (b[0] & 0x80) != 0 {
			p.y.Neg(p.y)
		}

		// Check that it's a valid point
		y2t := new(big.Int).Set(p.y)
		y2t.Mul(y2t, y2t)
		y2t.Mod(y2t, c.p.P)
		if y2t.Cmp(y2) == 0 {
			return p	// valid point
		}
		// otherwise try again...
	}
}

func (c *Curve) EncryptPoint(p Point, s Secret) Point {
	cp := p.(*CurvePoint)
	cs := s.(*CurveSecret)
	e := new(CurvePoint)
	e.c = c
	e.x,e.y = c.ScalarMult(cp.x,cp.y,cs.Int.Bytes())
	return e
}

func (c *Curve) EncodePoint(p Point) []byte {
	return p.(*CurvePoint).Encode()
}

func (c *Curve) DecodePoint(data []byte) (Point,error)	{
	p := new(CurvePoint)
	p.c = c
	p.Decode(data)
	if !c.ValidPoint(p) {
		return nil, errors.New("invalid curve point")
	}

	return p, nil
}

func (c *Curve) GroupOrder() *big.Int {
	return c.p.N
}


