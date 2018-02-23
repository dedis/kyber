package bn256

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/dedis/kyber"
)

///////////////////////////////////////////////////////////////////////////////
// Point G1
///////////////////////////////////////////////////////////////////////////////

type pointG1 struct {
	g *curvePoint
}

func newPointG1() *pointG1 {
	p := &pointG1{g: &curvePoint{}}
	return p
}

// Equal ...
func (p *pointG1) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

// Null ...
func (p *pointG1) Null() kyber.Point {
	p.g.SetInfinity()
	return p
}

// Base ...
func (p *pointG1) Base() kyber.Point {
	p.g.Set(curveGen)
	return p
}

// Pick ...
func (p *pointG1) Pick(rand cipher.Stream) kyber.Point {
	s := newScalar().Pick(rand)
	p.Base()
	p.g.Mul(p.g, s.(*scalar).x)
	return p
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
	// TODO check if/how G1 points can support data embedding
	return 0
}

// Embed ...
func (p *pointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	// TODO check if/how G1 points can support data embedding
	return nil
}

// Data ...
func (p *pointG1) Data() ([]byte, error) {
	// TODO check if/how G1 points can support data embedding
	return nil, nil
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

///////////////////////////////////////////////////////////////////////////////
// Point G2
///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
// Point GT
///////////////////////////////////////////////////////////////////////////////

type pointGT struct {
	g *gfP12
}

func newPointGT() *pointGT {
	p := &pointGT{g: &gfP12{}}
	return p
}

// Equal ...
func (p *pointGT) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

// Null ...
func (p *pointGT) Null() kyber.Point {
	p.g.Set(gfP12Inf)
	return p
}

// Base ...
func (p *pointGT) Base() kyber.Point {
	p.g.Set(gfP12Gen)
	return p
}

// Pick ...
func (p *pointGT) Pick(rand cipher.Stream) kyber.Point {
	s := newScalar().Pick(rand)
	p.Base()
	p.g.Exp(p.g, s.(*scalar).x)
	return p
}

// Set ...
func (p *pointGT) Set(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Set(x)
	return p
}

// Clone ...
func (p *pointGT) Clone() kyber.Point {
	q := newPointGT()
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
func (p *pointGT) EmbedLen() int {
	// TODO check if/how GT points can support data embedding
	return 0
}

// Embed ...
func (p *pointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	// TODO check if/how GT points can support data embedding
	return nil
}

// Data ...
func (p *pointGT) Data() ([]byte, error) {
	// TODO check if/how GT points can support data embedding
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
func (p *pointGT) Sub(a, b kyber.Point) kyber.Point {
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
	p.g.Exp(r, t)
	return p
}

// MarshalBinary ...
func (p *pointGT) MarshalBinary() ([]byte, error) {
	n := p.ElementSize()
	ret := make([]byte, p.MarshalSize())
	temp := &gfP{}

	montDecode(temp, &p.g.x.x.x)
	temp.Marshal(ret[0*n:])
	montDecode(temp, &p.g.x.x.y)
	temp.Marshal(ret[1*n:])
	montDecode(temp, &p.g.x.y.x)
	temp.Marshal(ret[2*n:])
	montDecode(temp, &p.g.x.y.y)
	temp.Marshal(ret[3*n:])
	montDecode(temp, &p.g.x.z.x)
	temp.Marshal(ret[4*n:])
	montDecode(temp, &p.g.x.z.y)
	temp.Marshal(ret[5*n:])
	montDecode(temp, &p.g.y.x.x)
	temp.Marshal(ret[6*n:])
	montDecode(temp, &p.g.y.x.y)
	temp.Marshal(ret[7*n:])
	montDecode(temp, &p.g.y.y.x)
	temp.Marshal(ret[8*n:])
	montDecode(temp, &p.g.y.y.y)
	temp.Marshal(ret[9*n:])
	montDecode(temp, &p.g.y.z.x)
	temp.Marshal(ret[10*n:])
	montDecode(temp, &p.g.y.z.y)
	temp.Marshal(ret[11*n:])

	return ret, nil
}

// MarshalTo ...
func (p *pointGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalBinary ...
func (p *pointGT) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if len(buf) < p.MarshalSize() {
		return errors.New("bn256: not enough data")
	}

	if p.g == nil {
		p.g = &gfP12{}
	}

	p.g.x.x.x.Unmarshal(buf[0*n:])
	p.g.x.x.y.Unmarshal(buf[1*n:])
	p.g.x.y.x.Unmarshal(buf[2*n:])
	p.g.x.y.y.Unmarshal(buf[3*n:])
	p.g.x.z.x.Unmarshal(buf[4*n:])
	p.g.x.z.y.Unmarshal(buf[5*n:])
	p.g.y.x.x.Unmarshal(buf[6*n:])
	p.g.y.x.y.Unmarshal(buf[7*n:])
	p.g.y.y.x.Unmarshal(buf[8*n:])
	p.g.y.y.y.Unmarshal(buf[9*n:])
	p.g.y.z.x.Unmarshal(buf[10*n:])
	p.g.y.z.y.Unmarshal(buf[11*n:])
	montEncode(&p.g.x.x.x, &p.g.x.x.x)
	montEncode(&p.g.x.x.y, &p.g.x.x.y)
	montEncode(&p.g.x.y.x, &p.g.x.y.x)
	montEncode(&p.g.x.y.y, &p.g.x.y.y)
	montEncode(&p.g.x.z.x, &p.g.x.z.x)
	montEncode(&p.g.x.z.y, &p.g.x.z.y)
	montEncode(&p.g.y.x.x, &p.g.y.x.x)
	montEncode(&p.g.y.x.y, &p.g.y.x.y)
	montEncode(&p.g.y.y.x, &p.g.y.y.x)
	montEncode(&p.g.y.y.y, &p.g.y.y.y)
	montEncode(&p.g.y.z.x, &p.g.y.z.x)
	montEncode(&p.g.y.z.y, &p.g.y.z.y)

	// TODO: check if point is on curve

	return nil
}

// UnmarshalFrom ...
func (p *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

// MarshalSize ...
func (p *pointGT) MarshalSize() int {
	return 12 * p.ElementSize()
}

// ElementSize ...
func (p *pointGT) ElementSize() int {
	return 256 / 8
}

// String ...
func (p *pointGT) String() string {
	return "bn256.GT" + p.g.String()
}

// Finalize ...
func (p *pointGT) Finalize() kyber.Point {
	buf := finalExponentiation(p.g)
	p.g.Set(buf)
	return p
}
