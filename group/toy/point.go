package toy

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/dedis/kyber"
)

type point uint

func (p *point) Equal(p2 kyber.Point) bool {
	return *p == *p2.(*point)
}

func (p *point) Null() kyber.Point {
	*p = 1
	return p
}

func (p *point) Base() kyber.Point {
	*p = 2
	return p
}

func (p *point) Pick(rand cipher.Stream) kyber.Point {
	var b [1]byte
	rand.XORKeyStream(b[:], b[:])
	*p = (1 << (scalar(b[0]) % GroupOrder)) % GroupModulus
	return p
}

func (p *point) Set(p2 kyber.Point) kyber.Point {
	*p = *p2.(*point)
	return p
}

func (p *point) Clone() kyber.Point {
	p2 := *p
	return &p2
}

func (p *point) EmbedLen() int {
	return 0
}

func (p *point) Embed(data []byte, r cipher.Stream) kyber.Point {
	return p.Pick(r)
}

func (p *point) Data() ([]byte, error) {
	return nil, nil
}

func (p *point) Add(a, b kyber.Point) kyber.Point {
	aP := a.(*point)
	bP := b.(*point)
	*p = *aP * *bP % GroupModulus
	return p
}

func (p *point) Sub(a, b kyber.Point) kyber.Point {
	p.Neg(b)
	p.Add(a, p)
	return p
}

func (p *point) Neg(a kyber.Point) kyber.Point {
	aV := *a.(*point)
	prod := point(1)
	for i := scalar(0); i < GroupOrder-1; i++ {
		prod = prod * aV % GroupModulus
	}
	*p = prod
	return p
}

func (p *point) Mul(s kyber.Scalar, p2 kyber.Point) kyber.Point {
	var p2Pv point
	if p2 == nil {
		p2Pv.Base()
	} else {
		p2Pv = *p2.(*point)
	}
	sv := *s.(*scalar)
	*p = 1
	for i := scalar(0); i < sv; i++ {
		*p = *p * p2Pv % GroupModulus
	}
	return p
}

func (p *point) String() string {
	return fmt.Sprint(*p)
}

func (p *point) MarshalSize() int {
	return 1
}

func (p *point) MarshalTo(w io.Writer) (int, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(b)
}

func (p *point) UnmarshalFrom(r io.Reader) (int, error) {
	var b [1]byte
	n := 0

	for {
		m, err := r.Read(b[:])
		n += m
		if m > 0 {
			err2 := p.UnmarshalBinary(b[:])
			if err2 == nil {
				return n, err
			}
		}
		if err != nil {
			return n, err
		}
	}
}

func (p *point) MarshalBinary() (data []byte, err error) {
	b := [1]byte{byte(*p)}
	return b[:], nil
}

func (p *point) UnmarshalBinary(data []byte) error {
	t := point(data[0]) % GroupModulus
	if t != 0 && t&(t-1) == 0 {
		*p = t
		return nil
	}
	return errors.New("Could not unmarshal")
}
