package circl_bls12381

import (
	"crypto/cipher"
	"io"

	circl "github.com/cloudflare/circl/ecc/bls12381"
	"go.dedis.ch/kyber/v3"
)

var gtBase *circl.Gt

func init() {
	gtBase = circl.Pair(circl.G1Generator(), circl.G2Generator())
}

var _ kyber.Point = &GTElt{}

type GTElt struct{ inner circl.Gt }

func (p *GTElt) MarshalBinary() (data []byte, err error) { return p.inner.MarshalBinary() }

func (p *GTElt) UnmarshalBinary(data []byte) error { return p.inner.UnmarshalBinary(data) }

func (p *GTElt) String() string { return p.inner.String() }

func (p *GTElt) MarshalSize() int { return circl.GtSize }

func (p *GTElt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *GTElt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *GTElt) Equal(p2 kyber.Point) bool { x := p2.(*GTElt); return p.inner.IsEqual(&x.inner) }

func (p *GTElt) Null() kyber.Point { p.inner.SetIdentity(); return p }

func (p *GTElt) Base() kyber.Point { p.inner = *gtBase; return p }

func (p *GTElt) Pick(rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*GTElt).inner; return p }

func (p *GTElt) Clone() kyber.Point { return new(GTElt).Set(p) }

func (p *GTElt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Embed(data []byte, r cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Add(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*GTElt), b.(*GTElt)
	p.inner.Mul(&aa.inner, &bb.inner)
	return p
}

func (p *GTElt) Sub(a, b kyber.Point) kyber.Point {
	return p.Add(a, new(GTElt).Neg(b))
}

func (p *GTElt) Neg(a kyber.Point) kyber.Point {
	aa := a.(*GTElt)
	p.inner.Inv(&aa.inner)
	return p
}

func (p *GTElt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	qq, ss := q.(*GTElt), s.(*Scalar)
	p.inner.Exp(&qq.inner, &ss.inner)
	return p
}
