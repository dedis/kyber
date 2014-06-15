package sodium

// #include "sc.h"
// #include "ge.h"
// #include "fe.h"
//
// void ge_p2_to_p3(ge_p3 *r,const ge_p2 *p) {
//	fe_copy(r->X,p->X);
//	fe_copy(r->Y,p->Y);
//	fe_copy(r->Z,p->Z);
//	fe_mul(r->T,p->X,p->Y);
// }
//
// void ge_neg(ge_p3 *r) {
//	fe_neg(r->X,r->X);
// }
//
// void ge_p3_add(ge_p3 *r,ge_p3 *a,ge_p3 *b) {
//	ge_cached bc;
//	ge_p1p1 t;
//	ge_p3_to_cached(&bc,b);
//	ge_add(&t,a,&bc);
//	ge_p1p1_to_p3(r,&t);
// }
//
import "C"

import (
	"bytes"
	"errors"
	"unsafe"
	//"runtime"
	"math/big"
	"encoding/hex"
	"crypto/cipher"
	"dissent/crypto"
)



type secret struct {
	b [32]byte
}

var s0 = secret{}
var s1 = secret{[32]byte{1}}
var s2 = secret{[32]byte{2}}
var s3 = secret{[32]byte{3}}
var s4 = secret{[32]byte{4}}

type point struct {
	p C.ge_p3
}

type curve struct {
}


// Convert little-endian byte slice to hex string
func tohex(s []byte) string {
	b := make([]byte, len(s))
	for i := range(b) {		// byte-swap to big-endian for display
		b[i] = s[31-i]
	}
	return hex.EncodeToString(b)
}

func (s *secret) String() string {
	return hex.EncodeToString(s.b[:])
}

func (s *secret) Encode() []byte { return s.b[:] }

func (s *secret) Decode(buf []byte) crypto.Secret {
	copy(s.b[:], buf)
	return s
}

func (s *secret) Equal(s2 crypto.Secret) bool {
	return bytes.Equal(s.b[:], s2.(*secret).b[:])
}

func (s *secret) Add(cx,cy crypto.Secret) crypto.Secret {
	x := cx.(*secret)
	y := cy.(*secret)

	// XXX using muladd is probably way overkill
	C.sc_muladd((*C.uchar)(unsafe.Pointer(&s.b[0])),
			(*C.uchar)(unsafe.Pointer(&x.b[0])),
			(*C.uchar)(unsafe.Pointer(&s1.b[0])),
			(*C.uchar)(unsafe.Pointer(&y.b[0])))

	return s
}
func (s *secret) Neg(x crypto.Secret) crypto.Secret {
	panic("XXX")
}
func (s *secret) Pick(rand cipher.Stream) crypto.Secret {
	rand.XORKeyStream(s.b[:], s.b[:])
	s.b[0] &= 248;
	s.b[31] &= 63;
	s.b[31] |= 64;
	return s
}



func (p *point) String() string {
	return hex.EncodeToString(p.Encode())
}

func (p *point) Equal(p2 crypto.Point) bool {
	return bytes.Equal(p.Encode(), p2.(*point).Encode())
}

func (p *point) Base() crypto.Point {

	// Way to kill a fly with a sledgehammer...
	r := C.ge_p2{}
	a := C.ge_p3{}
	C.ge_p3_0(&a)
	C.ge_double_scalarmult_vartime(&r,
				(*C.uchar)(unsafe.Pointer(&s0.b[0])),
				&p.p,
				(*C.uchar)(unsafe.Pointer(&s1.b[0])))
	C.ge_p2_to_p3(&p.p, &r)
	return p
}

func (p *point) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (32 - 8 - 8) / 8
}

func (p *point) Pick(data []byte,rand cipher.Stream) (crypto.Point, []byte) {
	panic("XXX")
}

func (p *point) Data() ([]byte,error) {
	panic("XXX")
}

func (p *point) Encrypt(ca crypto.Point, cs crypto.Secret) crypto.Point {
	a := ca.(*point)
	s := cs.(*secret)

	// We'd rather this NOT be vartime, but for now...
	// and we only need a single multiplication, not double.
	r := C.ge_p2{}
	C.ge_double_scalarmult_vartime(&r, (*C.uchar)(unsafe.Pointer(&s.b[0])),
				&a.p, (*C.uchar)(unsafe.Pointer(&s0.b[0])))
	C.ge_p2_to_p3(&p.p, &r)
	return p
}

func (p *point) Add(ca,cb crypto.Point) crypto.Point {
	a := ca.(*point)
	b := cb.(*point)

	C.ge_p3_add(&p.p, &a.p, &b.p)
/*
	bcached := C.ge_cached{}
	C.ge_p3_to_cached(&bcached, &b.p)
	r := C.ge_p1p1{}
	C.ge_add(&r, &a.p, &bcached)
	C.ge_p1p1_to_p3(&p.p, &r)
*/
/*
	r := C.ge_p2{}
	C.ge_double_scalarmult_vartime_2(&r,
				(*C.uchar)(unsafe.Pointer(&s1.b[0])), &a.p,
				(*C.uchar)(unsafe.Pointer(&s1.b[0])), &b.p)
	C.ge_p2_to_p3(&p.p, &r)
*/

	return p
}

func (p *point) Encode() []byte {
	buf := [32]byte{}
	C.ge_p3_tobytes((*C.uchar)(unsafe.Pointer(&buf[0])), &p.p)
	return buf[:]
}

func (p *point) Decode(buf []byte) (crypto.Point, error) {
	if len(buf) != 32 {
		return nil, errors.New("curve25519 point wrong size")
	}
	if C.ge_frombytes_negate_vartime(&p.p,
				(*C.uchar)(unsafe.Pointer(&buf[0]))) != 0 {
		return nil, errors.New("curve25519 point invalid")
	}
	C.ge_neg(&p.p)
	return p, nil
}

func (p *point) validate() {
	//println("validating:")
	//p.dump()
	p2,err := new(point).Decode(p.Encode())
	if err != nil || !p2.Equal(p) {
		panic("invalid point")
	}
	//p2.(*point).dump()
}

func fetohex(fe *C.fe) string {
	b := [32]byte{}
	C.fe_tobytes((*C.uchar)(unsafe.Pointer(&b[0])), &fe[0])
	return tohex(b[:])
}

func (p *point) dump() {
	println("X",fetohex(&p.p.X))
	println("Y",fetohex(&p.p.Y))
	println("Z",fetohex(&p.p.Z))
	println("T",fetohex(&p.p.T))
}



func (c *curve) SecretLen() int {
	return 32
}

func (c *curve) Secret() crypto.Secret {
	return new(secret)
}

func (c *curve) PointLen() int {
	return 32
}

func (c *curve) Point() crypto.Point {
	return new(point)
}

func (c *curve) Order() *big.Int {
	return new(big.Int)	// XXX
}

func NewCurve25519() crypto.Group {
	return new(curve)
}

func TestCurve25519() {

	var x point

	p0 := point{}
	C.ge_p3_0(&p0.p)
	println("zero",p0.String())
	p0.validate()

	b := point{}
	b.Base()
	println("base",b.String())
	b.dump()
	b.validate()

	x.Base()
	x.Encrypt(&x,&s0)
	println("base*0",x.String())
	x.validate()

	x.Base()
	x.Encrypt(&x,&s1)
	println("base*1",x.String())
	x.validate()

	bx2 := point{}
	bx2.Encrypt(&b,&s2)
	println("base*2",bx2.String())
	bx2.validate()

	r := C.ge_p1p1{}	// check against doubling function
	C.ge_p3_dbl(&r, &b.p)
	C.ge_p1p1_to_p3(&x.p,&r);
	println("base*2",x.String())
	x.validate()

	bx4 := point{}
	bx4.Encrypt(&b,&s4)
	println("base*4",bx4.String())
	bx4.validate()

	bx2x2 := point{}
	bx2x2.Encrypt(&bx2,&s2)
	println("base*2*2",bx2x2.String())
	bx2x2.validate()

	x.Add(&b,&p0)
	println("base+0",x.String())
	x.Add(&p0,&b)
	println("0+base",x.String())
	x.validate()
	x.validate()

	x.Add(&b,&b)
	println("base+base",x.String())
	//x.validate()

	x.Add(&b,&bx2)
	println("base+base*2",x.String())
	//x.validate()

	x.Add(&x,&b)
	println("base+base*3",x.String())
	//x.validate()

//	g := NewCurve25519()
//	crypto.TestGroup(g)
}

