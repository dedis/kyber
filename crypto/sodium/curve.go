package sodium

// #include "sc.h"
// #include "ge.h"
// #include "fe.h"
//
// void ge_p2_to_p3(ge_p3 *r,const ge_p2 *p) {
//   fe_copy(r->X,p->X);
//   fe_copy(r->Y,p->Y);
//   fe_copy(r->Z,p->Z);
//   fe_mul(r->T,p->X,p->Y);
// }
//
// void ge_neg(ge_p3 *r) {
//   fe_neg(r->X,r->X);
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

var szero = [32]byte{}
var sone = [32]byte{1}

type point struct {
	p C.ge_p3
}

type curve struct {
}


func (s *secret) String() string {
	b := make([]byte, 32)
	for i := range(b) {		// byte-swap to big-endian for display
		b[i] = s.b[31-i]
	}
	return hex.EncodeToString(b)
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
			(*C.uchar)(unsafe.Pointer(&sone[0])),
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

func (p *point) validate() {
	p2,err := new(point).Decode(p.Encode())
	if err != nil || !p2.Equal(p) {
		panic("invalid point")
	}
}

func (p *point) Base() crypto.Point {

	// Way to kill a fly with a sledgehammer...
	r := C.ge_p2{}
	a := C.ge_p3{}
	C.ge_p3_0(&a)
	C.ge_double_scalarmult_vartime(&r,
				(*C.uchar)(unsafe.Pointer(&szero[0])),
				&p.p,
				(*C.uchar)(unsafe.Pointer(&sone[0])))
	C.ge_p2_to_p3(&p.p, &r)
	println("base",p.String())

	nb := *p
	C.ge_neg(&nb.p)
	println("negb",nb.String())

	nb.Add(&nb,p)
	println("sum ",nb.String())
	nb.validate()

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
	println("base",a.String())
	println("secr",s.String())
	C.ge_double_scalarmult_vartime(&r, (*C.uchar)(unsafe.Pointer(&s.b[0])),
				&a.p, (*C.uchar)(unsafe.Pointer(&szero[0])))
	C.ge_p2_to_p3(&p.p, &r)
	println("encr",p.String())
	return p
}

func (p *point) Add(ca,cb crypto.Point) crypto.Point {
	a := ca.(*point)
	b := cb.(*point)

	bcached := C.ge_cached{}
	C.ge_p3_to_cached(&bcached, &b.p)

	r := C.ge_p1p1{}
	C.ge_add(&r, &a.p, &bcached)

	C.ge_p1p1_to_p3(&p.p, &r)
	p.validate()

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

