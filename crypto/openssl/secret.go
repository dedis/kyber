package openssl

// #include <openssl/bn.h>
//
// // Macros don't work so well with cgo, so de-macroize them in C
// int bn_zero(BIGNUM *bn) { return BN_zero(bn); }
// int bn_one(BIGNUM *bn) { return BN_one(bn); }
//
import "C"

import (
	"crypto/cipher"
	"dissent/crypto"
)


type secret struct {
	bignum
	c *curve
}


func newSecret(c *curve) *secret {
	s := new(secret)
	s.bignum.Init()
	s.c = c
	return s
}

func (s *secret) String() string { return s.BigInt().String() }

func (s *secret) Equal(s2 crypto.Secret) bool {
	return s.Cmp(&s2.(*secret).bignum) == 0
}

func (s *secret) Set(x crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	if C.BN_copy(s.bignum.bn, xs.bignum.bn) == nil {
		panic("BN_copy: "+getErrString())
	}
	return s
}

func (s *secret) Zero() crypto.Secret {
	if C.bn_zero(s.bignum.bn) == 0 {
		panic("BN_zero: "+getErrString())
	}
	return s
}

func (s *secret) One() crypto.Secret {
	if C.bn_one(s.bignum.bn) == 0 {
		panic("BN_one: "+getErrString())
	}
	return s
}

func (s *secret) SetInt64(v int64) crypto.Secret {
	vl := C.ulong(v)
	if int64(v) != v {
		panic("openssl.SetInt64: value doesn't fit into C.ulong")
	}
	if C.BN_set_word(s.bignum.bn, vl) == 0 {
		panic("BN_set_word: "+getErrString())
	}
	return s
}

func (s *secret) Add(x,y crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	if C.BN_mod_add(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, s.c.n.bn,
			s.c.ctx) == 0 {
		panic("BN_mod_add: "+getErrString())
	}
	return s
}

func (s *secret) Sub(x,y crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	if C.BN_mod_sub(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, s.c.n.bn,
			s.c.ctx) == 0 {
		panic("BN_mod_sub: "+getErrString())
	}
	return s
}

func (s *secret) Neg(x crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	if C.BN_mod_sub(s.bignum.bn, s.c.n.bn, xs.bignum.bn, s.c.n.bn,
			s.c.ctx) == 0 {
		panic("BN_mod_sub: "+getErrString())
	}
	return s
}

func (s *secret) Mul(x,y crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	if C.BN_mod_mul(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, s.c.n.bn,
			s.c.ctx) == 0 {
		panic("BN_mod_mul: "+getErrString())
	}
	return s
}

func (s *secret) Div(x,y crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	ys := y.(*secret)

	// First compute inverse of y, then multiply by x.
	// Must use a temporary in the case x == s.
	t := &s.bignum
	if x == s {
		t = newBigNum()
	}
	if C.BN_mod_inverse(t.bn, ys.bignum.bn, s.c.n.bn,
			s.c.ctx) == nil {
		panic("BN_mod_inverse: "+getErrString())
	}
	if C.BN_mod_mul(s.bignum.bn, xs.bignum.bn, t.bn, s.c.n.bn,
			s.c.ctx) == 0 {
		panic("BN_mod_mul: "+getErrString())
	}
	return s
}

func (s *secret) Inv(x crypto.Secret) crypto.Secret {
	xs := x.(*secret)
	if C.BN_mod_inverse(s.bignum.bn, xs.bignum.bn, s.c.n.bn,
			s.c.ctx) == nil {
		panic("BN_mod_inverse: "+getErrString())
	}
	return s
}

func (s *secret) Pick(rand cipher.Stream) crypto.Secret {
	s.bignum.RandMod(s.c.n,rand)
	return s
}

func (s *secret) Len() int {
	return s.c.nlen
}

func (s *secret) Encode() []byte {
	return s.Bytes()
}

func (s *secret) Decode(buf []byte) error {
	s.SetBytes(buf)
	return nil
}


