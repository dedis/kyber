package openssl

// #include <openssl/ec.h>
// #include <openssl/bn.h>
// #include <openssl/obj_mac.h>
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


type secret struct {
	bignum
}

type point struct {
	p *_Ctype_EC_POINT
	g *_Ctype_EC_GROUP
	c *curve
}

type curve struct {
//	m *_Ctype_EC_METHOD
	g *_Ctype_EC_GROUP
	p,n *bignum
	plen, nlen int
}

func newSecret(c *curve) *secret {
	s := new(secret)
	s.bignum.Init()
//	s.c = c
	return s
}

func (s *secret) String() string { return s.BigInt().String() }
func (s *secret) Encode() []byte { return s.Bytes() }
func (s *secret) Decode(buf []byte) crypto.Secret { s.SetBytes(buf); return s }
func (s *secret) Equal(s2 crypto.Secret) bool {
	return s.Cmp(&s2.(*secret).bignum) == 0
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
	return hex.EncodeToString(p.c.EncodePoint(p))
}
func (p *point) Valid() bool {
	return C.EC_POINT_is_on_curve(p.g, p.p, nil) != 0
}
func (p *point) Equal(p2 crypto.Point) bool {
	return C.EC_POINT_cmp(p.g, p.p, p2.(*point).p, nil) == 0
}
func (p *point) GetX() *bignum {
	x := newBigNum()
	if C.EC_POINT_get_affine_coordinates_GFp(p.c.g, p.p, x.bn, nil, nil) == 0 {
		panic("EC_POINT_get_affine_coordinates_GFp: "+getErrString())
	}
	return x
}
func (p *point) GetY() *bignum {
	y := newBigNum()
	if C.EC_POINT_get_affine_coordinates_GFp(p.c.g, p.p, nil, y.bn, nil) == 0 {
		panic("EC_POINT_get_affine_coordinates_GFp: "+getErrString())
	}
	return y
}
/*
func (p *point) Encode() []byte {
	l := 1+p.c.plen
	b := make([]byte,l)
	if C.EC_POINT_point2oct(p.g, p.p, C.POINT_CONVERSION_COMPRESSED,
			(*_Ctype_unsignedchar)(unsafe.Pointer(&b[0])),
			C.size_t(l), nil) != C.size_t(l) {
		panic("EC_POINT_point2oct: "+getErrString())
	}
	return b
}
func (p *point) Decode(buf []byte) (crypto.Point,error) {
	if C.EC_POINT_oct2point(p.g, p.p,
			(*_Ctype_unsignedchar)(unsafe.Pointer(&buf[0])),
			C.size_t(len(buf)), nil) == 0 {
		return nil,errors.New(getErrString())
	}
	return p
}
*/



func (c *curve) SecretLen() int {
	return c.nlen
}

func (c *curve) RandomSecret(rand cipher.Stream) crypto.Secret {
	s := newSecret(c)
	s.bignum.RandMod(c.n,rand)
	return s
}

func (c *curve) AddSecret(x, y crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	s := newSecret(c)
	if C.BN_mod_add(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, c.n.bn,
			nil) == 0 {
		panic("BN_mod_add: "+getErrString())
	}
	return s
}

func (c *curve) GroupOrder() *big.Int {
	return c.n.BigInt()
}

func (c *curve) PointLen() int {
	return 1+c.plen	// compressed encoding
}

func (c *curve) ValidPoint(p crypto.Point) bool {
	return p.(*point).Valid()
}

func (c *curve) BasePoint() crypto.Point {
	p := newPoint(c)
	genp := C.EC_GROUP_get0_generator(c.g)
	if genp == nil {
		panic("EC_GROUP_get0_generator: "+getErrString())
	}
	if C.EC_POINT_copy(p.p, genp) == 0 {
		panic("EC_POINT_copy: "+getErrString())
	}
	return p
}

func (c *curve) RandomPoint(rand cipher.Stream) crypto.Point {
	b := make([]byte, c.PointLen())
	for {
		// Pick a random compressed point, and try to decode it.
		// Decoding will fail if the point is not on the curve.
		rand.XORKeyStream(b,b)
		b[0] = (b[0] & 1) | 2	// COMPRESSED, random y bit

		p,err := c.DecodePoint(b)
		if err == nil {
			return p
		}

		// otherwise try again...
	}
}

func (c *curve) EmbedLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (c.p.BitLen() - 8 - 8) / 8
}

func (c *curve) EmbedPoint(data []byte,rand cipher.Stream) (crypto.Point,[]byte) {
	l := c.PointLen()

	dl := c.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	b := make([]byte, l)
	for {
		// Pick a random compressed point, and overlay the data.
		// Decoding will fail if the point is not on the curve.
		rand.XORKeyStream(b,b)
		b[0] = (b[0] & 1) | 2	// COMPRESSED, random y bit

		b[l-1] = byte(dl)		// Encode length in low 8 bits
		copy(b[l-dl-1:l-1],data)	// Copy in data to embed

		p,err := c.DecodePoint(b)	// See if it decodes!
		if err == nil {
			return p, data[dl:]
		}

		// otherwise try again...
	}
}

func (c *curve) Extract(p crypto.Point) ([]byte,error) {
	b := p.(*point).GetX().Bytes()		// we only need the X-coord
	l := c.plen
	dl := int(b[l-1])
	if dl > c.EmbedLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-1:l-1],nil
}

func (c *curve) EncryptPoint(cp crypto.Point, cs crypto.Secret) crypto.Point {
	p := cp.(*point)
	s := cs.(*secret)
	r := newPoint(c)
	if C.EC_POINT_mul(c.g, r.p, nil, p.p, s.bignum.bn, nil) == 0 {
		panic("EC_POINT_mul: "+getErrString())
	}
	return r
}

func (c *curve) EncodePoint(cp crypto.Point) []byte {
	p := cp.(*point)
	l := 1+c.plen
	b := make([]byte,l)
	if C.EC_POINT_point2oct(c.g, p.p, C.POINT_CONVERSION_COMPRESSED,
			(*_Ctype_unsignedchar)(unsafe.Pointer(&b[0])),
			C.size_t(l), nil) != C.size_t(l) {
		panic("EC_POINT_point2oct: "+getErrString())
	}
	return b
}

func (c *curve) DecodePoint(buf []byte) (crypto.Point,error) {
	p := newPoint(c)
	if C.EC_POINT_oct2point(p.g, p.p,
			(*_Ctype_unsignedchar)(unsafe.Pointer(&buf[0])),
			C.size_t(len(buf)), nil) == 0 {
		return nil,errors.New(getErrString())
	}
	return p,nil
}

func (c *curve) initNamedCurve(nid C.int) *curve {
//	c.m = C.EC_GFp_nistp256_method()
	c.g = C.EC_GROUP_new_by_curve_name(nid)
	if c.g == nil {
		panic("can't find create P256 curve: "+getErrString())
	}

	// Get this curve's prime field
	c.p = newBigNum()
	if C.EC_GROUP_get_curve_GFp(c.g, c.p.bn, nil, nil, nil) == 0 {
		panic("EC_GROUP_get_curve_GFp: "+getErrString())
	}
	c.plen = (c.p.BitLen()+7)/8

	// Get the curve's group order
	c.n = newBigNum()
	if C.EC_GROUP_get_order(c.g, c.n.bn, nil) == 0 {
		panic("EC_GROUP_get_order: "+getErrString())
	}
	c.nlen = (c.n.BitLen()+7)/8

	return c
}

func (c *curve) InitP256() {
	c.initNamedCurve(C.NID_X9_62_prime256v1)
}

