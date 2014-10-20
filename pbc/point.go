package pbc

// #include <stdlib.h>
// #include <pbc/pbc.h>
import "C"

import (
	"unsafe"
	"errors"
	"runtime"
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
)


// Elliptic curve point for G1,G2 groups
type point struct {
	e C.element_t
}

func clearPoint(p *point) {
	println("clearPoint",p)
	C.element_clear(&p.e[0])
}

func newCurvePoint() *point {
	p := new(point)
	runtime.SetFinalizer(p, clearPoint)
	return p
}

func (p *point) String() string {
	var b [256]byte
	l := C.element_snprint((*C.char)(unsafe.Pointer(&b[0])),
				(C.size_t)(len(b)), &p.e[0])
	if l <= 0 {
		panic("Can't convert pairing element to string")
	}
	return string(b[:l])
}

func (p *point) Equal(p2 abstract.Point) bool {
	return C.element_cmp(&p.e[0], &p2.(*point).e[0]) == 0
}

func (p *point) Null() abstract.Point {
	C.element_set1(&p.e[0])
	return p
}

func (p *point) Base() abstract.Point {
	panic("XXX")
}

func (p *point) PickLen() int {
	panic("XXX")
}

func (p *point) Pick(data []byte,rand cipher.Stream) (abstract.Point, []byte) {
	panic("XXX")
}

func (p *point) Data() ([]byte,error) {
	panic("XXX")
}

func (p *point) Add(a,b abstract.Point) abstract.Point {
	C.element_mul(&p.e[0], &a.(*point).e[0], &b.(*point).e[0])
	return p
}

func (p *point) Sub(a,b abstract.Point) abstract.Point {
	C.element_div(&p.e[0], &a.(*point).e[0], &b.(*point).e[0])
	return p
}

func (p *point) Neg(a abstract.Point) abstract.Point {
	C.element_invert(&p.e[0], &a.(*point).e[0])
	return p
}

func (p *point) Mul(b abstract.Point, s abstract.Secret) abstract.Point {
	if b == nil {
		return p.Base().Mul(p,s)
	}
	C.element_pow_zn(&p.e[0], &b.(*point).e[0], &s.(*secret).e[0])
	return p
}

func (p *point) Len() int {
	return int(C.element_length_in_bytes_compressed(&p.e[0]))
}

func (p *point) Encode() []byte {
	l := p.Len()
	b := make([]byte, l)
	a := C.element_to_bytes_compressed((*C.uchar)(unsafe.Pointer(&b[0])),
						&p.e[0])
	if int(a) != l {
		panic("Element encoding yielded wrong length")
	}
	return b
}

func (p *point) Decode(buf []byte) error {
	l := p.Len()
	if len(buf) != l {
		return errors.New("Encoded element wrong length")
	}
	a := C.element_from_bytes_compressed(&p.e[0],
					(*C.uchar)(unsafe.Pointer(&buf[0])))
	if int(a) != l {	// apparently doesn't return decoding errors
		panic("element_from_bytes consumed wrong number of bytes")
	}
	return nil
}

