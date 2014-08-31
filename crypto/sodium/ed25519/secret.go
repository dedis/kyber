package ed25519

// #include "sc.h"
//
import "C"

import (
	"bytes"
	"unsafe"
	//"runtime"
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

func (s *secret) Set(s2 crypto.Secret) crypto.Secret {
	s.b = s2.(*secret).b
	return s
}

func (s *secret) String() string {
	return hex.EncodeToString(s.b[:])
}

func (s *secret) Len() int { return 32 }

func (s *secret) Encode() []byte { return s.b[:] }

func (s *secret) Decode(buf []byte) error {
	copy(s.b[:], buf)
	return nil
}

func (s *secret) Zero() crypto.Secret {
	panic("XXX")
}

func (s *secret) One() crypto.Secret {
	panic("XXX")
}

func (s *secret) SetInt64(v int64) crypto.Secret {
	panic("XXX")
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

func (s *secret) Sub(cx,cy crypto.Secret) crypto.Secret {
	panic("XXX")
}

func (s *secret) Neg(x crypto.Secret) crypto.Secret {
	panic("XXX")
}

func (s *secret) Mul(cx,cy crypto.Secret) crypto.Secret {
	panic("XXX")
}

func (s *secret) Div(cx,cy crypto.Secret) crypto.Secret {
	panic("XXX")
}

func (s *secret) Inv(x crypto.Secret) crypto.Secret {
	panic("XXX")
}

func (s *secret) Pick(rand cipher.Stream) crypto.Secret {
	rand.XORKeyStream(s.b[:], s.b[:])
	s.b[0] &= 248;
	s.b[31] &= 63;
	s.b[31] |= 64;
	return s
}


