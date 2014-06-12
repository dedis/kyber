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
func (s *CurveSecret) Add(a,b Secret) Secret {
	s.Int.Add(&a.(*CurveSecret).Int,&b.(*CurveSecret).Int)
	s.Int.Mod(&s.Int, s.c.p.N)
	return s
}
func (s *CurveSecret) Pick(rand cipher.Stream) Secret {
	s.Int.Set(BigIntMod(s.c.p.N,rand))
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
func (p *CurvePoint) Decode(buf []byte) (Point,error) {
	p.x,p.y = elliptic.Unmarshal(p.c, buf)
	if p.x == nil {
		return nil,errors.New("invalid elliptic curve point")
	}
	return p,nil
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

func (c *Curve) Secret() Secret {
	s := new(CurveSecret)
	s.c = c
	return s
}


// Number of bytes required to store one coordinate on this curve
func (c *Curve) coordLen() int {
	return (c.p.BitSize+7)/8
}

// Number of bytes required to store a marshalled (but uncompressed) point
func (c *Curve) PointLen() int {
	return 1+2*c.coordLen()	// ANSI X9.62: 1 header byte plus 2 coords
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

// Try to generate a point on this curve from a chosen x-coordinate,
// with a random sign.
func (c *Curve) genPoint(x *big.Int, rand cipher.Stream) (Point,bool) {

	// Compute the corresponding Y coordinate, if any
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	y2.Sub(y2, threeX)
	y2.Add(y2, c.p.B)
	y2.Mod(y2, c.p.P)
	y := c.sqrt(y2)

	// Pick a random sign for the y coordinate
	b := make([]byte,1)
	rand.XORKeyStream(b,b)
	if (b[0] & 0x80) != 0 {
		y.Neg(y)
	}

	// Check that it's a valid point
	y2t := new(big.Int).Mul(y, y)
	y2t.Mod(y2t, c.p.P)
	if y2t.Cmp(y2) != 0 {
		return nil,false	// Doesn't yield a valid point!
	}

	p := new(CurvePoint)
	p.c = c
	p.x = x
	p.y = y
	return p,true
}

func (c *Curve) RandomPoint(rand cipher.Stream) Point {
	for {
		// Pick a random x,y coordinate with the correct modulus
		x := BigIntMod(c.p.P, rand)
		p,suc := c.genPoint(x,rand)
		if suc {
			return p	// valid point
		}
		// otherwise try again...
	}
}

func (c *Curve) EmbedLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (c.p.P.BitLen() - 8 - 8) / 8
}

// Pick a curve point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
func (c *Curve) EmbedPoint(data []byte,
				rand cipher.Stream) (Point,[]byte) {

	l := c.coordLen()

	dl := c.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		xb := BigIntMod(c.p.P, rand).Bytes()
println("bigint len",len(xb)) 
		xb[l-1] = byte(dl)		// Encode length in low 8 bits
		copy(xb[l-dl-1:l-1],data)	// Copy in data to embed
		p,suc := c.genPoint(new(big.Int).SetBytes(xb), rand)
		if suc {
			return p, data[dl:]
		}
	}
}

// Extract embedded data from a Schnorr group element
func (c *Curve) Extract(p Point) ([]byte,error) {
	b := p.(*CurvePoint).x.Bytes()
	l := c.coordLen()
	dl := int(b[l-1])
	if dl > c.EmbedLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-1:l-1],nil
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


