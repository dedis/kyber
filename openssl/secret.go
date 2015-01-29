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
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/group"
	"io"
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

func (s *secret) Equal(s2 abstract.Secret) bool {
	return s.Cmp(&s2.(*secret).bignum) == 0
}

func (s *secret) Set(x abstract.Secret) abstract.Secret {
	xs := x.(*secret)
	if C.BN_copy(s.bignum.bn, xs.bignum.bn) == nil {
		panic("BN_copy: " + getErrString())
	}
	return s
}

func (s *secret) Zero() abstract.Secret {
	if C.bn_zero(s.bignum.bn) == 0 {
		panic("BN_zero: " + getErrString())
	}
	return s
}

func (s *secret) One() abstract.Secret {
	if C.bn_one(s.bignum.bn) == 0 {
		panic("BN_one: " + getErrString())
	}
	return s
}

func (s *secret) SetInt64(v int64) abstract.Secret {
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}

	// Initialize the absolute value
	vl := C.BN_ULONG(v)
	if int64(v) != v {
		panic("openssl.SetInt64: value doesn't fit into C.ulong")
	}
	if C.BN_set_word(s.bignum.bn, vl) == 0 {
		panic("BN_set_word: " + getErrString())
	}

	// Negate if needed
	if neg {
		if C.BN_sub(s.bignum.bn, s.c.n.bn, s.bignum.bn) == 0 {
			panic("BN_sub: " + getErrString())
		}
	}

	return s
}

func (s *secret) Add(x, y abstract.Secret) abstract.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	if C.BN_mod_add(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, s.c.n.bn,
		s.c.ctx) == 0 {
		panic("BN_mod_add: " + getErrString())
	}
	return s
}

func (s *secret) Sub(x, y abstract.Secret) abstract.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	if C.BN_mod_sub(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, s.c.n.bn,
		s.c.ctx) == 0 {
		panic("BN_mod_sub: " + getErrString())
	}
	return s
}

func (s *secret) Neg(x abstract.Secret) abstract.Secret {
	xs := x.(*secret)
	if C.BN_mod_sub(s.bignum.bn, s.c.n.bn, xs.bignum.bn, s.c.n.bn,
		s.c.ctx) == 0 {
		panic("BN_mod_sub: " + getErrString())
	}
	return s
}

func (s *secret) Mul(x, y abstract.Secret) abstract.Secret {
	xs := x.(*secret)
	ys := y.(*secret)
	if C.BN_mod_mul(s.bignum.bn, xs.bignum.bn, ys.bignum.bn, s.c.n.bn,
		s.c.ctx) == 0 {
		panic("BN_mod_mul: " + getErrString())
	}
	return s
}

func (s *secret) Div(x, y abstract.Secret) abstract.Secret {
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
		panic("BN_mod_inverse: " + getErrString())
	}
	if C.BN_mod_mul(s.bignum.bn, xs.bignum.bn, t.bn, s.c.n.bn,
		s.c.ctx) == 0 {
		panic("BN_mod_mul: " + getErrString())
	}
	return s
}

func (s *secret) Inv(x abstract.Secret) abstract.Secret {
	xs := x.(*secret)
	if C.BN_mod_inverse(s.bignum.bn, xs.bignum.bn, s.c.n.bn,
		s.c.ctx) == nil {
		panic("BN_mod_inverse: " + getErrString())
	}
	return s
}

func (s *secret) Pick(rand cipher.Stream) abstract.Secret {
	s.bignum.RandMod(s.c.n, rand)
	return s
}

func (s *secret) MarshalSize() int {
	return s.c.nlen
}

func (s *secret) MarshalBinary() ([]byte, error) {
	return s.Bytes(s.c.nlen), nil
}

func (s *secret) UnmarshalBinary(buf []byte) error {
	s.SetBytes(buf)
	return nil
}

func (s *secret) MarshalTo(w io.Writer) (int, error) {
	return group.SecretMarshalTo(s, w)
}

func (s *secret) UnmarshalFrom(r io.Reader) (int, error) {
	return group.SecretUnmarshalFrom(s, r)
}
