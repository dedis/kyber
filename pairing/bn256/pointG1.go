package bn256

import (
	"crypto/cipher"
	"errors"
	"io"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
)

type pointG1 struct {
	g *curvePoint
}

func newPointG1() *pointG1 {
	p := &pointG1{g: &curvePoint{}}
	return p
}

// Equal ...
func (p *pointG1) Equal(q kyber.Point) bool {
	x := q.(*pointG1).g
	p.g.Neg(x)      // p = -q
	p.g.Add(p.g, x) // p = -q + q
	return p.g.IsInfinity()
}

// Null ...
func (p *pointG1) Null() kyber.Point {
	q := newPointG1()
	q.g.SetInfinity()
	return q
}

// Base ...
func (p *pointG1) Base() kyber.Point {
	q := newPointG1()
	q.g.Set(curveGen)
	return q
}

// Pick ...
func (p *pointG1) Pick(rand cipher.Stream) kyber.Point {
	return p.Embed(nil, rand)
}

// Set ...
func (p *pointG1) Set(q kyber.Point) kyber.Point {
	x := q.(*pointG1).g
	p.g.Set(x)
	return p
}

// Clone ...
func (p *pointG1) Clone() kyber.Point {
	q := newPointG1()
	buf, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if err := q.UnmarshalBinary(buf); err != nil {
		panic(err)
	}
	return q
}

// EmbedLen ...
func (p *pointG1) EmbedLen() int {
	// TODO: check if this makes sense
	return 256/8 - 1 - 1
}

// Embed ...
func (p *pointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	// TODO: check if/how G1 points can support embedding
	l := p.EmbedLen()
	if len(data) < l {
		l = len(data)
	}
	for {
		// fill in random bytes
		buf := make([]byte, p.MarshalSize())
		random.Bytes(buf, rand)
		if data != nil {
			buf[0] = byte(l)       // encode length in the low 8 bits
			copy(buf[1:1+l], data) // copy data
		}

		if p.UnmarshalBinary(buf) == nil {
			break // found a valid point
		}
	}
	return p
}

// Data ...
func (p *pointG1) Data() ([]byte, error) {
	// TODO: check if this works for G1 points
	buf, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	l := int(buf[0]) // get length byte
	if l > p.EmbedLen() {
		return nil, errors.New("bn256: invalid length of embedded data")
	}
	return buf[1 : 1+l], nil
}

// Add ...
func (p *pointG1) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointG1).g
	y := b.(*pointG1).g
	p.g.Add(x, y) // p = a + b
	return p
}

// Sub ...
func (p *pointG1) Sub(a, b kyber.Point) kyber.Point {
	x := a.(*pointG1).g
	y := b.(*pointG1).g
	p.g.Neg(x)      // p = -b
	p.g.Add(p.g, y) // p = p + a = -b + a
	return p
}

// Neg ...
func (p *pointG1) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointG1).g
	p.g.Neg(x)
	return p
}

// Mul ...
func (p *pointG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG1().Base()
	}
	t := s.(*scalar).x
	r := q.(*pointG1).g
	p.g.Mul(r, t)
	return p
}

// MarshalBinary ...
func (p *pointG1) MarshalBinary() ([]byte, error) {
	n := p.ElementSize()
	p.g.MakeAffine()
	ret := make([]byte, p.MarshalSize())
	if p.g.IsInfinity() {
		return ret, nil
	}
	tmp := &gfP{}
	montDecode(tmp, &p.g.x)
	tmp.Marshal(ret)
	montDecode(tmp, &p.g.y)
	tmp.Marshal(ret[n:])
	return ret, nil
}

// MarshalTo ...
func (p *pointG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalBinary ...
func (p *pointG1) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if len(buf) < p.MarshalSize() {
		return errors.New("bn256: not enough data")
	}
	if p.g == nil {
		p.g = &curvePoint{}
	} else {
		p.g.x, p.g.y = gfP{0}, gfP{0}
	}

	p.g.x.Unmarshal(buf)
	p.g.y.Unmarshal(buf[n:])
	montEncode(&p.g.x, &p.g.x)
	montEncode(&p.g.y, &p.g.y)

	zero := gfP{0}
	if p.g.x == zero && p.g.y == zero {
		// This is the point at infinity
		p.g.y = *newGFp(1)
		p.g.z = gfP{0}
		p.g.t = gfP{0}
	} else {
		p.g.z = *newGFp(1)
		p.g.t = *newGFp(1)
	}

	if !p.g.IsOnCurve() {
		return errors.New("bn256: malformed point")
	}

	return nil
}

// UnmarshalFrom ...
func (p *pointG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

// MarshalSize ...
func (p *pointG1) MarshalSize() int {
	return 2 * p.ElementSize()
}

// ElementSize ...
func (p *pointG1) ElementSize() int {
	return 256 / 8
}

// String ...
func (p *pointG1) String() string {
	return "bn256.G1" + p.g.String()
}
