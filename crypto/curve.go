package crypto

import (
	"errors"
	"math/big"
	"crypto/cipher"
	"crypto/elliptic"
)


type CurveSecret struct {
	i big.Int 
	c *Curve
}

func (s *CurveSecret) String() string { return s.i.String() }
func (s *CurveSecret) Equal(s2 Secret) bool {
	return s.i.Cmp(&s2.(*CurveSecret).i) == 0
}
func (s *CurveSecret) Neg(a Secret) Secret {
	i := &a.(*CurveSecret).i
	if i.Sign() > 0 {
		s.i.Sub(s.c.p.N, i)
	} else {
		s.i.SetUint64(0)
	}
	return s
}
func (s *CurveSecret) Encode() []byte { return s.i.Bytes() }
func (s *CurveSecret) Decode(buf []byte) Secret {
	s.i.SetBytes(buf)
	return s
}
func (s *CurveSecret) Add(a,b Secret) Secret {
	s.i.Add(&a.(*CurveSecret).i,&b.(*CurveSecret).i)
	s.i.Mod(&s.i, s.c.p.N)
	return s
}
func (s *CurveSecret) Pick(rand cipher.Stream) Secret {
	s.i.Set(RandomBigInt(s.c.p.N,rand))
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

func (p *CurvePoint) Base() Point {
	p.x = p.c.p.Gx
	p.y = p.c.p.Gy
	return p
}

func (p *CurvePoint) Valid() bool {
	return p.c.IsOnCurve(p.x,p.y)
}

// Try to generate a point on this curve from a chosen x-coordinate,
// with a random sign.
func (p *CurvePoint) genPoint(x *big.Int, rand cipher.Stream) bool {

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
	b := make([]byte,1)
	rand.XORKeyStream(b,b)
	if (b[0] & 0x80) != 0 {
		y.Neg(y)
	}

	// Check that it's a valid point
	y2t := new(big.Int).Mul(y, y)
	y2t.Mod(y2t, p.c.p.P)
	if y2t.Cmp(y2) != 0 {
		return false	// Doesn't yield a valid point!
	}

	p.x = x
	p.y = y
	return true
}

func (p *CurvePoint) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (p.c.p.P.BitLen() - 8 - 8) / 8
}

// Pick a curve point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
func (p *CurvePoint) Pick(data []byte, rand cipher.Stream) (Point, []byte) {

	l := p.c.coordLen()
	dl := p.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := RandomBits(uint(p.c.p.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)	// Encode length in low 8 bits
			copy(b[l-dl-1:l-1],data) // Copy in data to embed
		}
		if p.genPoint(new(big.Int).SetBytes(b), rand) {
			return p, data[dl:]
		}
	}
}

// Extract embedded data from a Schnorr group element
func (p *CurvePoint) Data() ([]byte,error) {
	b := p.x.Bytes()
	l := p.c.coordLen()
	if len(b) < l {		// pad leading zero bytes if necessary
		b = append(make([]byte,l-len(b)), b...)
	}
	dl := int(b[l-1])
	if dl > p.PickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-1:l-1],nil
}

func (p *CurvePoint) Encrypt(b Point, s Secret) Point {
	cb := b.(*CurvePoint)
	cs := s.(*CurveSecret)
	p.x,p.y = p.c.ScalarMult(cb.x,cb.y,cs.i.Bytes())
	return p
}

func (p *CurvePoint) Add(a,b Point) Point {
	ca := a.(*CurvePoint)
	cb := b.(*CurvePoint)
	p.x,p.y = p.c.Add(ca.x, ca.y, cb.x, cb.y)
	return p
}

func (p *CurvePoint) Encode() []byte {
	return elliptic.Marshal(p.c, p.x, p.y)
}

func (p *CurvePoint) Decode(buf []byte) (Point, error) {
	p.x,p.y = elliptic.Unmarshal(p.c, buf)
	if p.x == nil || !p.Valid() {
		return nil, errors.New("invalid elliptic curve point")
	}
	return p, nil
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

func (c *Curve) Point() Point {
	p := new(CurvePoint)
	p.c = c
	return p
}

func (c *Curve) Order() *big.Int {
	return c.p.N
}


