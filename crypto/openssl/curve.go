package openssl

// #include <openssl/ec.h>
// #include <openssl/bn.h>
// #include <openssl/obj_mac.h>
//
// struct bignum_ctx {
// };
//
// struct ec_group_st {		// CGo doesn't like undefined C structs
// };
//
// struct ec_point_st {
// };
//
import "C"

import (
	"errors"
	"unsafe"
	"runtime"
	"math/big"
	"encoding/hex"
	"crypto/cipher"
	"dissent/crypto"
)


type point struct {
	p *_Ctype_struct_ec_point_st
	g *_Ctype_struct_ec_group_st
	c *curve
}

type curve struct {
	ctx *_Ctype_struct_bignum_ctx
	g *_Ctype_struct_ec_group_st
	p,n *bignum
	plen, nlen int
	name string
}


func newPoint(c *curve) *point {
	p := new(point)
	p.c = c
	p.g = c.g
	p.p = C.EC_POINT_new(c.g)
	runtime.SetFinalizer(p, freePoint)
	return p
}

func freePoint (p *point) {
	C.EC_POINT_free(p.p)
	p.p = nil
}

func (p *point) String() string {
	return hex.EncodeToString(p.Encode())
}
func (p *point) Valid() bool {
	return C.EC_POINT_is_on_curve(p.g, p.p, p.c.ctx) != 0
}
func (p *point) Equal(p2 crypto.Point) bool {
	return C.EC_POINT_cmp(p.g, p.p, p2.(*point).p, p.c.ctx) == 0
}
func (p *point) GetX() *bignum {
	x := newBigNum()
	if C.EC_POINT_get_affine_coordinates_GFp(p.c.g, p.p, x.bn, nil,
			p.c.ctx) == 0 {
		panic("EC_POINT_get_affine_coordinates_GFp: "+getErrString())
	}
	return x
}
func (p *point) GetY() *bignum {
	y := newBigNum()
	if C.EC_POINT_get_affine_coordinates_GFp(p.c.g, p.p, nil, y.bn,
			p.c.ctx) == 0 {
		panic("EC_POINT_get_affine_coordinates_GFp: "+getErrString())
	}
	return y
}

func (p *point) Null() crypto.Point {
	if C.EC_POINT_set_to_infinity(p.c.g, p.p) == 0 {
		panic("EC_POINT_set_to_infinity: "+getErrString())
	}
	return p
}

func (p *point) Base() crypto.Point {
	genp := C.EC_GROUP_get0_generator(p.c.g)
	if genp == nil {
		panic("EC_GROUP_get0_generator: "+getErrString())
	}
	if C.EC_POINT_copy(p.p, genp) == 0 {
		panic("EC_POINT_copy: "+getErrString())
	}
	return p
}

func (p *point) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (p.c.p.BitLen() - 8 - 8) / 8
}

func (p *point) Pick(data []byte,rand cipher.Stream) (crypto.Point, []byte) {

	l := p.c.PointLen()
	dl := p.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	b := make([]byte, l)
	for {
		// Pick a random compressed point, and overlay the data.
		// Decoding will fail if the point is not on the curve.
		rand.XORKeyStream(b,b)
		b[0] = (b[0] & 1) | 2	// COMPRESSED, random y bit

		if data != nil {
			b[l-1] = byte(dl)	// Encode length in low 8 bits
			copy(b[l-dl-1:l-1],data) // Copy in data to embed
		}

		if err := p.Decode(b); err == nil {	// See if it decodes!
			return p, data[dl:]
		}

		// otherwise try again...
	}
}

func (p *point) Data() ([]byte,error) {
	b := p.GetX().Bytes()		// we only need the X-coord
	l := p.c.plen
	if len(b) < l {		// pad leading zero bytes if necessary
		b = append(make([]byte,l-len(b)), b...)
	}
	dl := int(b[l-1])
	if dl > p.PickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-1:l-1],nil
}

func (p *point) Add(ca,cb crypto.Point) crypto.Point {
	a := ca.(*point)
	b := cb.(*point)
	if C.EC_POINT_add(p.c.g, p.p, a.p, b.p, p.c.ctx) == 0 {
		panic("EC_POINT_add: "+getErrString())
	}
	return p
}

func (p *point) Sub(ca,cb crypto.Point) crypto.Point {
	a := ca.(*point)
	b := cb.(*point)
	// Add the point inverse
	if C.EC_POINT_copy(p.p, b.p) == 0 {
		panic("EC_POINT_copy: "+getErrString())
	}
	if C.EC_POINT_invert(p.c.g, p.p, p.c.ctx) == 0 {
		panic("EC_POINT_invert: "+getErrString())
	}
	if C.EC_POINT_add(p.c.g, p.p, a.p, p.p, p.c.ctx) == 0 {
		panic("EC_POINT_add: "+getErrString())
	}
	return p
}

func (p *point) Mul(cb crypto.Point, cs crypto.Secret) crypto.Point {
	b := cb.(*point)
	s := cs.(*secret)
	if C.EC_POINT_mul(p.c.g, p.p, nil, b.p, s.bignum.bn, p.c.ctx) == 0 {
		panic("EC_POINT_mul: "+getErrString())
	}
	return p
}

// XXX use precomputed generator optimization
func (p *point) BaseMul(s crypto.Secret) crypto.Point {
	p.Base()
	p.Mul(p,s)
	return p
}


func (p *point) Len() int {
	return 1+p.c.plen	// compressed encoding
}

func (p *point) Encode() []byte {
	l := 1+p.c.plen
	b := make([]byte,l)
	if C.EC_POINT_point2oct(p.c.g, p.p, C.POINT_CONVERSION_COMPRESSED,
			(*_Ctype_unsignedchar)(unsafe.Pointer(&b[0])),
			C.size_t(l), p.c.ctx) != C.size_t(l) {
		panic("EC_POINT_point2oct: "+getErrString())
	}
	return b
}

func (p *point) Decode(buf []byte) error {
	if C.EC_POINT_oct2point(p.g, p.p,
			(*_Ctype_unsignedchar)(unsafe.Pointer(&buf[0])),
			C.size_t(len(buf)), p.c.ctx) == 0 {
		return errors.New(getErrString())
	}
	return nil
}



func (c *curve) String() string {
	return c.name
}

func (c *curve) SecretLen() int {
	return c.nlen
}

func (c *curve) Secret() crypto.Secret {
	s := newSecret(c)
	s.c = c
	return s
}

func (c *curve) PointLen() int {
	return 1+c.plen	// compressed encoding
}

func (c *curve) Point() crypto.Point {
	return newPoint(c)
}

func (c *curve) Order() *big.Int {
	return c.n.BigInt()
}

func (c *curve) initNamedCurve(name string, nid C.int) *curve {
	c.name = name

	c.ctx = C.BN_CTX_new()
	if c.ctx == nil {
		panic("C.BN_CTX_new: "+getErrString())
	}

	c.g = C.EC_GROUP_new_by_curve_name(nid)
	if c.g == nil {
		panic("can't find create P256 curve: "+getErrString())
	}

	// Get this curve's prime field
	c.p = newBigNum()
	if C.EC_GROUP_get_curve_GFp(c.g, c.p.bn, nil, nil, c.ctx) == 0 {
		panic("EC_GROUP_get_curve_GFp: "+getErrString())
	}
	c.plen = (c.p.BitLen()+7)/8

	// Get the curve's group order
	c.n = newBigNum()
	if C.EC_GROUP_get_order(c.g, c.n.bn, c.ctx) == 0 {
		panic("EC_GROUP_get_order: "+getErrString())
	}
	c.nlen = (c.n.BitLen()+7)/8

	return c
}

func (c *curve) InitP224() {
	c.initNamedCurve("P224", C.NID_secp224r1)
}

func (c *curve) InitP256() {
	c.initNamedCurve("P256", C.NID_X9_62_prime256v1)
}

func (c *curve) InitP384() {
	c.initNamedCurve("P384", C.NID_secp384r1)
}

func (c *curve) InitP521() {
	c.initNamedCurve("P521", C.NID_secp521r1)
}

