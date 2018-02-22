package bn256

import (
	"crypto/cipher"
	"io"

	"github.com/dedis/kyber"
)

type pointGT struct {
	g *gfP12
}

func newPointGT() *pointGT {
	p := &pointGT{g: &gfP12{}}
	return p
}

// Equal ...
func (p *pointGT) Equal(q kyber.Point) bool {
	return false
}

// Null ...
func (p *pointGT) Null() kyber.Point {
	return nil
}

// Base ...
func (p *pointGT) Base() kyber.Point {
	a := newPointG1().Base()
	b := newPointG2().Base()
	q := newPointGT()
	q.Pair(a, b)
	return q
}

// Pick ...
func (p *pointGT) Pick(rand cipher.Stream) kyber.Point {
	return nil
}

// Set ...
func (p *pointGT) Set(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Set(x)
	return p
}

// Clone ...
func (p *pointGT) Clone() kyber.Point {
	return nil
}

// EmbedLen ...
func (p *pointGT) EmbedLen() int {
	return 0
}

// Embed ...
func (p *pointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	return nil
}

// Data ...
func (p *pointGT) Data() ([]byte, error) {
	return nil, nil
}

// Add ...
func (p *pointGT) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointGT).g
	y := b.(*pointGT).g
	p.g.Mul(x, y)
	return p
}

// Sub ...
func (p *pointGT) Sub(a, b, kyber.Point) kyber.Point {
	x := a.(*pointGT).g
	y := b.(*pointGT).g
	p.g.Neg(x)      // p = -b
	p.g.Add(p.g, y) // p = p + a = -b + a
	return p
}

// Neg ...
func (p *pointGT) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Conjugate(x)
	return p
}

// Mul ...
func (p *pointGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointGT().Base()
	}
	t := s.(*scalar).x
	r := q.(*pointGT).g
	p.g.Mul(r, t)
	return p
}

// MarshalBinary ...
func (p *pointGT) MarshalBinary() ([]byte, error) {
	return nil, nil
}

// MarshalTo ...
func (p *pointGT) MarshalTo(w io.Writer) (int, error) {
	return 0, nil
}

// UnmarshalBinary ...
func (p *pointGT) UnmarshalBinary(buf []byte) error {
	return nil
}

// UnmarshalFrom ...
func (p *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	return 0, nil
}

// MarshalSize ...
func (p *pointGT) MarshalSize() int {
	return 12 * p.ElementSize()
}

func (p *pointGT) ElementSize() int {
	return 256 / 8
}

// String ...
func (p *pointGT) String() string {
	return "bn256.GT" + p.g.String()
}

// Pair ...
func (p *pointGT) Pair(g1, g2 kyber.Point) kyber.Point {
	a := g1.(*pointG1).g
	b := g1.(*pointG2).g
	p.Set(optimalAte(a, b))
	return p
}

// Pair, Miller
