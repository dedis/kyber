package pbc

// #include <stdlib.h>
// #include <pbc/pbc.h>
import "C"

import (
	"unsafe"
	"errors"
	"runtime"
	"crypto/cipher"
	"dissent/crypto"
)


// Integer finite field point for GT group.
// Basically the same as 'point' type,
// except uses uncompressed rather than compressed encoding
// (since compressed encoding only works with curve points).
// Redundancy might be eliminated if PBC library
// generalizes or abstracts its compressed-encoding methods.
type intPoint struct {
	e C.element_t
}

func clearIntPoint(p *intPoint) {
	println("clearIntPoint",p)
	C.element_clear(&p.e[0])
}

func newIntPoint() *intPoint {
	p := new(intPoint)
	runtime.SetFinalizer(p, clearIntPoint)
	return p
}

func (p *intPoint) String() string {
	var b [256]byte
	l := C.element_snprint((*C.char)(unsafe.Pointer(&b[0])),
				(C.size_t)(len(b)), &p.e[0])
	if l <= 0 {
		panic("Can't convert pairing element to string")
	}
	return string(b[:l])
}

func (p *intPoint) Equal(p2 crypto.Point) bool {
	return C.element_cmp(&p.e[0], &p2.(*intPoint).e[0]) == 0
}

func (p *intPoint) Null() crypto.Point {
	C.element_set1(&p.e[0])
	return p
}

func (p *intPoint) Base() crypto.Point {
	panic("XXX")
}

func (p *intPoint) PickLen() int {
	panic("XXX")
}

func (p *intPoint) Pick(data []byte,rand cipher.Stream) (crypto.Point, []byte) {
	panic("XXX")
}

func (p *intPoint) Data() ([]byte,error) {
	panic("XXX")
}

func (p *intPoint) Add(a,b crypto.Point) crypto.Point {
	C.element_mul(&p.e[0], &a.(*intPoint).e[0], &b.(*intPoint).e[0])
	return p
}

func (p *intPoint) Sub(a,b crypto.Point) crypto.Point {
	C.element_div(&p.e[0], &a.(*intPoint).e[0], &b.(*intPoint).e[0])
	return p
}

func (p *intPoint) Mul(b crypto.Point, s crypto.Secret) crypto.Point {
	if b == nil {
		return p.Base().Mul(p,s)
	}
	C.element_pow_zn(&p.e[0], &b.(*intPoint).e[0], &s.(*secret).e[0])
	return p
}

// Pairing operation, satisfying PairingPoint interface for GT group.
func (p *intPoint) Pairing(p1,p2 crypto.Point) crypto.Point {
	C.element_pairing(&p.e[0], &p1.(*point).e[0], &p2.(*point).e[0])
	return p
}

func (p *intPoint) Len() int {
	return int(C.element_length_in_bytes(&p.e[0]))
}

func (p *intPoint) Encode() []byte {
	l := p.Len()
	b := make([]byte, l)
	a := C.element_to_bytes((*C.uchar)(unsafe.Pointer(&b[0])), &p.e[0])
	if int(a) != l {
		panic("Element encoding yielded wrong length")
	}
	return b
}

func (p *intPoint) Decode(buf []byte) error {
	l := p.Len()
	if len(buf) != l {
		return errors.New("Encoded element wrong length")
	}
	a := C.element_from_bytes(&p.e[0], (*C.uchar)(unsafe.Pointer(&buf[0])))
	if int(a) != l {	// apparently doesn't return decoding errors
		panic("element_from_bytes consumed wrong number of bytes")
	}
	return nil
}

