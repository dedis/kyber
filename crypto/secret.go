package crypto

import (
	"math/big"
	//"encoding/hex"
	"crypto/cipher"
)


// Generic Secret implementation using Go's built-in bignum library
type bigSecret struct {
	i big.Int 		// the secret
	q *big.Int		// group order (modulus for secret arithmetic)
}

func newBigSecret(q *big.Int) *bigSecret {
	s := new(bigSecret)
	s.q = q
	return s
}

func (s *bigSecret) String() string { return s.i.String() }

func (s *bigSecret) Equal(s2 Secret) bool {
	return s.i.Cmp(&s2.(*bigSecret).i) == 0
}

func (s *bigSecret) Set(a Secret) Secret {
	s.i.Set(&a.(*bigSecret).i)
	return s
}

func (s *bigSecret) Zero() Secret {
	s.i.SetInt64(0)
	return s
}

func (s *bigSecret) One() Secret {
	s.i.SetInt64(1)
	return s
}

func (s *bigSecret) Add(a,b Secret) Secret {
	s.i.Add(&a.(*bigSecret).i,&b.(*bigSecret).i)
	s.i.Mod(&s.i, s.q)
	return s
}

func (s *bigSecret) Sub(a,b Secret) Secret {
	s.i.Sub(&a.(*bigSecret).i,&b.(*bigSecret).i)
	s.i.Mod(&s.i, s.q)
	return s
}

func (s *bigSecret) Neg(a Secret) Secret {
	i := &a.(*bigSecret).i
	if i.Sign() > 0 {
		s.i.Sub(s.q, i)
	} else {
		s.i.SetUint64(0)
	}
	return s
}

func (s *bigSecret) Mul(a,b Secret) Secret {
	s.i.Mul(&a.(*bigSecret).i,&b.(*bigSecret).i)
	s.i.Mod(&s.i, s.q)
	return s
}

func (s *bigSecret) Div(a,b Secret) Secret {
	var t big.Int
	s.i.Mul(&a.(*bigSecret).i, t.ModInverse(&b.(*bigSecret).i, s.q))
	s.i.Mod(&s.i, s.q)
	return s
}

func (s *bigSecret) Inv(a Secret) Secret {
	s.i.ModInverse(&a.(*bigSecret).i, s.q)
	return s
}

func (s *bigSecret) Pick(rand cipher.Stream) Secret {
	s.i.Set(RandomBigInt(s.q,rand))
	return s
}

func (s *bigSecret) Len() int {
	return (s.q.BitLen()+7)/8
}

func (s *bigSecret) Encode() []byte {
	l := s.Len()
	b := s.i.Bytes()	// may be shorter than l
	if ofs := l-len(b); ofs != 0 {
		nb := make([]byte,l)
		copy(nb[ofs:],b)
		return nb
	}
	return b
}

func (s *bigSecret) Decode(buf []byte) error {
	s.i.SetBytes(buf)
	return nil
}

