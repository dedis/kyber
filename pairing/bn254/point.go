package bn254

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"golang.org/x/crypto/sha3"
)

var marshalPointID1 = [8]byte{'b', 'n', '2', '5', '4', '.', 'g', '1'}
var marshalPointID2 = [8]byte{'b', 'n', '2', '5', '4', '.', 'g', '2'}
var marshalPointIDT = [8]byte{'b', 'n', '2', '5', '4', '.', 'g', 't'}

type pointG1 struct {
	g   *curvePoint
	dst []byte
}

func newPointG1(dst []byte) *pointG1 {
	p := &pointG1{g: &curvePoint{}, dst: dst}
	return p
}

func (p *pointG1) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

func (p *pointG1) Null() kyber.Point {
	p.g.SetInfinity()
	return p
}

func (p *pointG1) Base() kyber.Point {
	p.g.Set(curveGen)
	return p
}

func (p *pointG1) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, Order).Pick(rand)
	p.Base()
	p.g.Mul(p.g, &s.(*mod.Int).V)
	return p
}

func (p *pointG1) Set(q kyber.Point) kyber.Point {
	x := q.(*pointG1).g
	p.g.Set(x)
	return p
}

// Clone makes a hard copy of the point
func (p *pointG1) Clone() kyber.Point {
	q := newPointG1(p.dst)
	q.g = p.g.Clone()
	return q
}

func (p *pointG1) EmbedLen() int {
	panic("bn254.G1: unsupported operation")
}

func (p *pointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	// XXX: An approach to implement this is:
	// - Encode data as the x-coordinate of a point on y²=x³+3 where len(data)
	//   is stored in the least significant byte of x and the rest is being
	//   filled with random values, i.e., x = rand || data || len(data).
	// - Use the Tonelli-Shanks algorithm to compute the y-coordinate.
	// - Convert the new point to Jacobian coordinates and set it as p.
	panic("bn254.G1: unsupported operation")
}

func (p *pointG1) Data() ([]byte, error) {
	panic("bn254.G1: unsupported operation")
}

func (p *pointG1) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointG1).g
	y := b.(*pointG1).g
	p.g.Add(x, y) // p = a + b
	return p
}

func (p *pointG1) Sub(a, b kyber.Point) kyber.Point {
	q := newPointG1(p.dst)
	return p.Add(a, q.Neg(b))
}

func (p *pointG1) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointG1).g
	p.g.Neg(x)
	return p
}

func (p *pointG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG1(p.dst).Base()
	}
	t := s.(*mod.Int).V
	r := q.(*pointG1).g
	p.g.Mul(r, &t)
	return p
}

func (p *pointG1) MarshalBinary() ([]byte, error) {
	// Clone is required as we change the point
	p = p.Clone().(*pointG1)

	n := p.ElementSize()
	// Take a copy so that p is not written to, so calls to MarshalBinary
	// are threadsafe.
	pgtemp := *p.g
	pgtemp.MakeAffine()
	ret := make([]byte, p.MarshalSize())
	if pgtemp.IsInfinity() {
		return ret, nil
	}
	tmp := &gfP{}
	montDecode(tmp, &pgtemp.x)
	tmp.Marshal(ret)
	montDecode(tmp, &pgtemp.y)
	tmp.Marshal(ret[n:])
	return ret, nil
}

func (p *pointG1) MarshalID() [8]byte {
	return marshalPointID1
}

func (p *pointG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *pointG1) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if len(buf) < p.MarshalSize() {
		return errors.New("bn254.G1: not enough data")
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
		return errors.New("bn254.G1: malformed point")
	}

	return nil
}

func (p *pointG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *pointG1) MarshalSize() int {
	return 2 * p.ElementSize()
}

func (p *pointG1) ElementSize() int {
	return 256 / 8
}

func (p *pointG1) String() string {
	return "bn254.G1" + p.g.String()
}

func (p *pointG1) Hash(m []byte) kyber.Point {
	return hashToPoint(p.dst, m)
}

func hashToPoint(domain, m []byte) kyber.Point {
	e0, e1 := hashToField(domain, m)
	p0 := mapToPoint(domain, e0)
	p1 := mapToPoint(domain, e1)
	p := p0.Add(p0, p1)
	return p
}

func hashToField(domain, m []byte) (*gfP, *gfP) {
	const u = 48
	_msg := expandMsgXmdKeccak256(domain, m, 2*u)
	x, y := new(big.Int), new(big.Int)
	x.SetBytes(_msg[0:48]).Mod(x, p)
	y.SetBytes(_msg[48:96]).Mod(y, p)
	gx, gy := &gfP{}, &gfP{}
	gx.Unmarshal(zeroPadBytes(x.Bytes(), 32))
	gy.Unmarshal(zeroPadBytes(y.Bytes(), 32))
	montEncode(gx, gx)
	montEncode(gy, gy)
	return gx, gy
}

// `mapToPoint` implements the general Shallue-van de Woestijne mapping to BN254 G1
// RFC9380, 6.6.1. https://datatracker.ietf.org/doc/html/rfc9380#name-shallue-van-de-woestijne-me
func mapToPoint(domain []byte, u *gfP) kyber.Point {
	tv1 := &gfP{}
	tv1.Set(u)
	gfpMul(tv1, tv1, tv1)
	gfpMul(tv1, tv1, c1)
	tv2 := &gfP{}
	gfpAdd(tv2, newGFp(1), tv1)
	negTv1 := &gfP{}
	gfpNeg(negTv1, tv1)
	gfpAdd(tv1, newGFp(1), negTv1)
	tv3 := &gfP{}
	gfpMul(tv3, tv1, tv2)
	tv3.Invert(tv3)
	tv5 := &gfP{}
	gfpMul(tv5, u, tv1)
	gfpMul(tv5, tv5, tv3)
	gfpMul(tv5, tv5, c3)
	x1 := &gfP{}
	gfpSub(x1, c2, tv5)
	x2 := &gfP{}
	gfpAdd(x2, c2, tv5)
	tv7 := &gfP{}
	gfpMul(tv7, tv2, tv2)
	tv8 := &gfP{}
	gfpMul(tv8, tv7, tv3)
	x3 := &gfP{}
	gfpMul(x3, tv8, tv8)
	gfpMul(x3, c4, x3)
	gfpAdd(x3, newGFp(1), x3)

	x, y := &gfP{}, &gfP{}
	if legendre(g(x1)) == 1 {
		x = x1
		y.Sqrt(g(x1))
	} else if legendre(g(x2)) == 1 {
		x = x2
		y.Sqrt(g(x2))
	} else {
		x = x3
		y.Sqrt(g(x3))
	}
	if sgn0(u) != sgn0(y) {
		gfpNeg(y, y)
	}

	p := newPointG1(domain).Base().(*pointG1)
	p.g.x.Set(x)
	p.g.y.Set(y)
	return p
}

// `expandMsgXmdKeccak256` implements expand_message_xmd from IETF RFC9380 Sec 5.3.1
// Borrowed from: https://github.com/kilic/bls12-381/blob/master/hash_to_field.go
func expandMsgXmdKeccak256(domain, msg []byte, outLen int) []byte {
	h := sha3.NewLegacyKeccak256()
	domainLen := uint8(len(domain))
	if domainLen > 255 {
		panic("invalid domain length")
	}
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			tmp[j] = b0[j] ^ bi[j]
		}
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])
	return out[:outLen]
}

type pointG2 struct {
	g   *twistPoint
	dst []byte
}

func newPointG2(dst []byte) *pointG2 {
	p := &pointG2{g: &twistPoint{}, dst: dst}
	return p
}

func (p *pointG2) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

func (p *pointG2) Null() kyber.Point {
	p.g.SetInfinity()
	return p
}

func (p *pointG2) Base() kyber.Point {
	p.g.Set(twistGen)
	return p
}

func (p *pointG2) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, Order).Pick(rand)
	p.Base()
	p.g.Mul(p.g, &s.(*mod.Int).V)
	return p
}

func (p *pointG2) Set(q kyber.Point) kyber.Point {
	x := q.(*pointG2).g
	p.g.Set(x)
	return p
}

// Clone makes a hard copy of the field
func (p *pointG2) Clone() kyber.Point {
	q := newPointG2(p.dst)
	q.g = p.g.Clone()
	return q
}

func (p *pointG2) EmbedLen() int {
	panic("bn254.G2: unsupported operation")
}

func (p *pointG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bn254.G2: unsupported operation")
}

func (p *pointG2) Data() ([]byte, error) {
	panic("bn254.G2: unsupported operation")
}

func (p *pointG2) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointG2).g
	y := b.(*pointG2).g
	p.g.Add(x, y) // p = a + b
	return p
}

func (p *pointG2) Sub(a, b kyber.Point) kyber.Point {
	q := newPointG2(p.dst)
	return p.Add(a, q.Neg(b))
}

func (p *pointG2) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointG2).g
	p.g.Neg(x)
	return p
}

func (p *pointG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG2(p.dst).Base()
	}
	t := s.(*mod.Int).V
	r := q.(*pointG2).g
	p.g.Mul(r, &t)
	return p
}

func (p *pointG2) MarshalBinary() ([]byte, error) {
	// Clone is required as we change the point during the operation
	p = p.Clone().(*pointG2)

	n := p.ElementSize()
	if p.g == nil {
		p.g = &twistPoint{}
	}

	p.g.MakeAffine()

	ret := make([]byte, p.MarshalSize())
	if p.g.IsInfinity() {
		return ret, nil
	}

	temp := &gfP{}
	montDecode(temp, &p.g.x.x)
	temp.Marshal(ret[0*n:])
	montDecode(temp, &p.g.x.y)
	temp.Marshal(ret[1*n:])
	montDecode(temp, &p.g.y.x)
	temp.Marshal(ret[2*n:])
	montDecode(temp, &p.g.y.y)
	temp.Marshal(ret[3*n:])

	return ret, nil
}

func (p *pointG2) MarshalID() [8]byte {
	return marshalPointID2
}

func (p *pointG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *pointG2) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if p.g == nil {
		p.g = &twistPoint{}
	}

	if len(buf) < p.MarshalSize() {
		return errors.New("bn254.G2: not enough data")
	}

	p.g.x.x.Unmarshal(buf[0*n:])
	p.g.x.y.Unmarshal(buf[1*n:])
	p.g.y.x.Unmarshal(buf[2*n:])
	p.g.y.y.Unmarshal(buf[3*n:])
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
			return errors.New("bn254.G2: malformed point")
		}
	}
	return nil
}

func (p *pointG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *pointG2) MarshalSize() int {
	return 4 * p.ElementSize()
}

func (p *pointG2) ElementSize() int {
	return 256 / 8
}

func (p *pointG2) String() string {
	return "bn254.G2" + p.g.String()
}

type pointGT struct {
	g *gfP12
}

func newPointGT() *pointGT {
	p := &pointGT{g: &gfP12{}}
	return p
}

func (p *pointGT) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

func (p *pointGT) Null() kyber.Point {
	// TODO: This can be a precomputed constant
	p.Pair(newPointG1([]byte{}).Null(), newPointG2([]byte{}).Null())
	return p
}

func (p *pointGT) Base() kyber.Point {
	// TODO: This can be a precomputed constant
	p.Pair(newPointG1([]byte{}).Base(), newPointG2([]byte{}).Base())
	return p
}

func (p *pointGT) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, Order).Pick(rand)
	p.Base()
	p.g.Exp(p.g, &s.(*mod.Int).V)
	return p
}

func (p *pointGT) Set(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Set(x)
	return p
}

// Clone makes a hard copy of the point
func (p *pointGT) Clone() kyber.Point {
	q := newPointGT()
	q.g = p.g.Clone()
	return q
}

func (p *pointGT) EmbedLen() int {
	panic("bn254.GT: unsupported operation")
}

func (p *pointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bn254.GT: unsupported operation")
}

func (p *pointGT) Data() ([]byte, error) {
	panic("bn254.GT: unsupported operation")
}

func (p *pointGT) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointGT).g
	y := b.(*pointGT).g
	p.g.Mul(x, y)
	return p
}

func (p *pointGT) Sub(a, b kyber.Point) kyber.Point {
	q := newPointGT()
	return p.Add(a, q.Neg(b))
}

func (p *pointGT) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Conjugate(x)
	return p
}

func (p *pointGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointGT().Base()
	}
	t := s.(*mod.Int).V
	r := q.(*pointGT).g
	p.g.Exp(r, &t)
	return p
}

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

func (p *pointGT) MarshalID() [8]byte {
	return marshalPointIDT
}

func (p *pointGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *pointGT) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if len(buf) < p.MarshalSize() {
		return errors.New("bn254.GT: not enough data")
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

func (p *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *pointGT) MarshalSize() int {
	return 12 * p.ElementSize()
}

func (p *pointGT) ElementSize() int {
	return 256 / 8
}

func (p *pointGT) String() string {
	return "bn254.GT" + p.g.String()
}

func (p *pointGT) Finalize() kyber.Point {
	buf := finalExponentiation(p.g)
	p.g.Set(buf)
	return p
}

func (p *pointGT) Miller(p1, p2 kyber.Point) kyber.Point {
	a := p1.(*pointG1).g
	b := p2.(*pointG2).g
	p.g.Set(miller(b, a))
	return p
}

func (p *pointGT) Pair(p1, p2 kyber.Point) kyber.Point {
	a := p1.(*pointG1).g
	b := p2.(*pointG2).g
	p.g.Set(optimalAte(b, a))
	return p
}
