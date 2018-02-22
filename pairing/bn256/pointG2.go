package bn256

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/dedis/kyber"
)

type pointG2 struct {
	g *twistPoint
}

func newPointG2() *pointG2 {
	p := &pointG2{g: &twistPoint{}}
	return p
}

// Equal ...
func (p *pointG2) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

// Null ...
func (p *pointG2) Null() kyber.Point {
	p.g.SetInfinity()
	return p
}

// Base ...
func (p *pointG2) Base() kyber.Point {
	p.g.Set(twistGen)
	return p
}

// Pick ...
func (p *pointG2) Pick(rand cipher.Stream) kyber.Point {
	s := newScalar().Pick(rand)
	p.Base()
	p.g.Mul(p.g, s.(*scalar).x)
	return p
}

// Set ...
func (p *pointG2) Set(q kyber.Point) kyber.Point {
	x := q.(*pointG2).g
	p.g.Set(x)
	return p
}

// Clone ...
func (p *pointG2) Clone() kyber.Point {
	q := newPointG2()
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
func (p *pointG2) EmbedLen() int {
	// TODO check if/how G2 points can support data embedding
	return 0
}

// Embed ...
func (p *pointG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	// TODO check if/how G2 points can support data embedding
	return nil
}

// Data ...
func (p *pointG2) Data() ([]byte, error) {
	// TODO check if/how G2 points can support data embedding
	return nil, nil
}

// Add ...
func (p *pointG2) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointG2).g
	y := b.(*pointG2).g
	p.g.Add(x, y) // p = a + b
	return p
}

// Sub ...
func (p *pointG2) Sub(a, b kyber.Point) kyber.Point {
	x := a.(*pointG2).g
	y := b.(*pointG2).g
	p.g.Neg(x)      // p = -b
	p.g.Add(p.g, y) // p = p + a = -b + a
	return p
}

// Neg ...
func (p *pointG2) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointG2).g
	p.g.Neg(x)
	return p
}

// Mul ...
func (p *pointG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG2().Base()
	}
	t := s.(*scalar).x
	r := q.(*pointG2).g
	p.g.Mul(r, t)
	return p
}

// MarshalBinary ...
func (p *pointG2) MarshalBinary() ([]byte, error) {
	n := p.ElementSize()
	if p.g == nil {
		p.g = &twistPoint{}
	}

	p.g.MakeAffine()
	if p.g.IsInfinity() {
		return make([]byte, 1), nil
	}

	ret := make([]byte, p.MarshalSize())
	ret[0] = 0x01
	temp := &gfP{}

	montDecode(temp, &p.g.x.x)
	temp.Marshal(ret[1+0*n:])
	montDecode(temp, &p.g.x.y)
	temp.Marshal(ret[1+1*n:])
	montDecode(temp, &p.g.y.x)
	temp.Marshal(ret[1+2*n:])
	montDecode(temp, &p.g.y.y)
	temp.Marshal(ret[1+3*n:])

	return ret, nil
}

// MarshalTo ...
func (p *pointG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalBinary ...
func (p *pointG2) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if p.g == nil {
		p.g = &twistPoint{}
	}

	if len(buf) > 0 && buf[0] == 0x00 {
		p.g.SetInfinity()
		//return buf[1:], nil
		return nil
	} else if len(buf) > 0 && buf[0] != 0x01 {
		return errors.New("bn256: malformed point")
	} else if len(buf) < p.MarshalSize() {
		return errors.New("bn256: not enough data")
	}

	p.g.x.x.Unmarshal(buf[1+0*n:])
	p.g.x.y.Unmarshal(buf[1+1*n:])
	p.g.y.x.Unmarshal(buf[1+2*n:])
	p.g.y.y.Unmarshal(buf[1+3*n:])
	montEncode(&p.g.x.x, &p.g.x.x)
	montEncode(&p.g.x.y, &p.g.x.y)
	montEncode(&p.g.y.x, &p.g.y.x)
	montEncode(&p.g.y.y, &p.g.y.y)

	if p.g.x.IsZero() && p.g.y.IsZero() {
		// This is the point at infinity.
		p.g.y.SetOne()
		p.g.z.SetZero()
		p.g.t.SetZero()
	} else {
		p.g.z.SetOne()
		p.g.t.SetOne()

		if !p.g.IsOnCurve() {
			return errors.New("bn256: malformed point")
		}
	}
	return nil
}

// UnmarshalFrom ...
func (p *pointG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

// MarshalSize ...
func (p *pointG2) MarshalSize() int {
	return 4*p.ElementSize() + 1
}

// ElementSize
func (p *pointG2) ElementSize() int {
	return 256 / 8
}

// String ...
func (p *pointG2) String() string {
	return "bn256.G2" + p.g.String()
}
