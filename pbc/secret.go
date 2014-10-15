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


type secret struct {
	e C.element_t
}


func clearSecret(s *secret) {
	println("clearSecret",s)
	C.element_clear(&s.e[0])
}

func newSecret() *secret {
	s := new(secret)
	runtime.SetFinalizer(s, clearSecret)
	return s
}

func (s *secret) String() string {
	var b [256]byte
	l := C.element_snprint((*C.char)(unsafe.Pointer(&b[0])),
				C.size_t(len(b)), &s.e[0])
	if l <= 0 {
		panic("Can't convert pairing element to string")
	}
	return string(b[:l])
}

func (s *secret) Equal(s2 crypto.Secret) bool {
	return C.element_cmp(&s.e[0], &s2.(*secret).e[0]) == 0
}

func (s *secret) Set(x crypto.Secret) crypto.Secret {
	C.element_set(&s.e[0], &x.(*secret).e[0])
	return s
}

func (s *secret) Zero() crypto.Secret {
	C.element_set0(&s.e[0])
	return s
}

func (s *secret) One() crypto.Secret {
	C.element_set0(&s.e[0])
	return s
}

func (s *secret) SetInt64(v int64) crypto.Secret {
	vl := C.long(v)
	if int64(vl) != v {
		panic("Oops, int64 initializer doesn't fit into C.ulong")
	}
	var z C.mpz_t
	C.mpz_init(&z[0])
	C.mpz_set_si(&z[0], vl)
	C.element_set_mpz(&s.e[0], &z[0])
	C.mpz_clear(&z[0])
	return s
}

func (s *secret) Pick(rand cipher.Stream) crypto.Secret {
	panic("XXX")
}

func (s *secret) Add(a,b crypto.Secret) crypto.Secret {
	C.element_add(&s.e[0], &a.(*secret).e[0], &b.(*secret).e[0])
	return s
}

func (s *secret) Sub(a,b crypto.Secret) crypto.Secret {
	C.element_sub(&s.e[0], &a.(*secret).e[0], &b.(*secret).e[0])
	return s
}

func (s *secret) Neg(a crypto.Secret) crypto.Secret {
	C.element_neg(&s.e[0], &a.(*secret).e[0])
	return s
}

func (s *secret) Mul(a,b crypto.Secret) crypto.Secret {
	C.element_mul(&s.e[0], &a.(*secret).e[0], &b.(*secret).e[0])
	return s
}

func (s *secret) Div(a,b crypto.Secret) crypto.Secret {
	C.element_div(&s.e[0], &a.(*secret).e[0], &b.(*secret).e[0])
	return s
}

func (s *secret) Inv(a crypto.Secret) crypto.Secret {
	C.element_invert(&s.e[0], &a.(*secret).e[0])
	return s
}

func (s *secret) Len() int {
	return int(C.element_length_in_bytes(&s.e[0]))
}

func (s *secret) Encode() []byte {
	l := s.Len()
	b := make([]byte, l)
	a := C.element_to_bytes((*C.uchar)(unsafe.Pointer(&b[0])),
				&s.e[0])
	if int(a) != l {
		panic("Element encoding yielded wrong length")
	}
	return b
}

func (s *secret) Decode(buf []byte) error {
	l := s.Len()
	if len(buf) != l {
		return errors.New("Encoded element wrong length")
	}
	a := C.element_from_bytes(&s.e[0], (*C.uchar)(unsafe.Pointer(&buf[0])))
	if int(a) != l {	// apparently doesn't return decoding errors
		panic("element_from_bytes consumed wrong number of bytes")
	}
	return nil
}

