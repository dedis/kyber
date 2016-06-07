package ed25519

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

// maxModulo needed because of some inconsistencies in nist.Int:
// if you want to have a prime order modulo as a secret
// (to use with Point.Mul()), then its MarshalBinary needs to return the same
// endianess with the secret defined here, i.e. LittleEndian. Using
// marshalbinary needs the MarshalSize which looks for the modulo
// (of the modulo!)
// Here it defines the maximum value allowed in 32 bytes, namely
// 2^256 - 1. It is ONLY to be used to define constants secrets are really
// *constants* !! If you add two secret with this *maxModulo* you might loose
// a value, namely 2^256 -1
var maxModulo, _ = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

type secret struct {
	*nist.Int
	prefix []byte
}

func newSecret() *secret {
	return &secret{
		Int: nist.NewInt(0, &primeOrder.Int.V),
	}
}

func newSecretFromInt64(v int64) *secret {
	return &secret{
		Int: nist.NewInt(v, &primeOrder.Int.V),
	}
}

func newSecretFromString(str string, b int) *secret {
	i, _ := new(nist.Int).SetString(str, "", b)
	i.M = maxModulo
	return &secret{
		Int: i,
	}
}

func newSecretFromBytes(buff []byte) *secret {
	s := newSecret()
	s.SetLittleEndian(buff)
	return s
}

func (s *secret) Equal(s2 abstract.Secret) bool {
	return s.Int.Equal(s2.(*secret).Int)
}

func (s *secret) Set(a abstract.Secret) abstract.Secret {
	s.Int.Set(a.(*secret).Int)
	return s
}
func (s *secret) SetInt64(v int64) abstract.Secret {
	s.Int.SetInt64(v)
	return s
}

func (s *secret) Zero() abstract.Secret {
	s.Int.Zero()
	return s
}

func (s *secret) Add(a, b abstract.Secret) abstract.Secret {
	s.Int.Add(a.(*secret).Int, b.(*secret).Int)
	return s
}

func (s *secret) Sub(a, b abstract.Secret) abstract.Secret {
	s.Int.Sub(a.(*secret).Int, b.(*secret).Int)
	return s
}

func (s *secret) Neg(a abstract.Secret) abstract.Secret {
	s.Int.Neg(a.(*secret).Int)
	return s
}

func (s *secret) One() abstract.Secret {
	s.Int.One()
	return s
}

func (s *secret) Mul(a, b abstract.Secret) abstract.Secret {
	s.Int.Mul(a.(*secret).Int, b.(*secret).Int)
	return s
}

func (s *secret) Div(a, b abstract.Secret) abstract.Secret {
	s.Int.Div(a.(*secret).Int, b.(*secret).Int)
	return s
}

func (s *secret) Inv(a abstract.Secret) abstract.Secret {
	s.Int.Inv(a.(*secret).Int)
	return s
}

func (s *secret) Pick(rand cipher.Stream) abstract.Secret {
	pre := random.Bytes(32, rand)
	expandedSecretKey := sha512.Sum512(pre)
	expandedSecretKey[0] &= 0xf8
	expandedSecretKey[31] &= 0x3f
	expandedSecretKey[31] |= 0x40

	s.Int.SetLittleEndian(expandedSecretKey[:32])
	s.prefix = expandedSecretKey[32:]
	return s
}

func (s *secret) MarshalBinary() ([]byte, error) {
	return s.Int.LittleEndian(32, 32), nil
}

func (s *secret) UnmarshalBinary(buff []byte) error {
	if len(buff) != s.MarshalSize() {
		return errors.New("Int.Decode: wrong size buffer")
	}
	s.Int.SetLittleEndian(buff)
	return nil
}

func (s *secret) String() string {
	return hex.EncodeToString(s.Int.LittleEndian(32, 32))
}

func (s *secret) setString(str, d string, base int) (*secret, bool) {
	_, b := s.Int.SetString(str, d, base)
	return s, b
}
