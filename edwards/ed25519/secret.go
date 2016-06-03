package ed25519

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

type secret struct {
	*nist.Int
}

func newSecret() *secret {
	return &secret{
		Int: nist.NewInt(0, &primeOrder.V),
	}
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
	s.Mul(a.(*secret).Int, b.(*secret).Int)
	return s
}

func (s *secret) Div(a, b abstract.Secret) abstract.Secret {
	s.Div(a.(*secret).Int, b.(*secret).Int)
	return s
}

func (s *secret) Inv(a abstract.Secret) abstract.Secret {
	s.Inv(a.(*secret).Int)
	return s
}

func (s *secret) Pick(rand cipher.Stream) abstract.Secret {
	pre := random.Bytes(32, rand)
	expandedSecretKey := sha512.Sum512(pre)
	expandedSecretKey[0] &= 0xf8
	expandedSecretKey[31] &= 0x3f
	expandedSecretKey[31] |= 0x40
	s.Int.SetLittleEndian(expandedSecretKey[:])
	return s
}

func (s *secret) MarshalBinary() ([]byte, error) {
	return s.LittleEndian(32, 32), nil
}

func (s *secret) UnmarshalBinary(buff []byte) error {
	if len(buff) != s.MarshalSize() {
		return errors.New("Int.Decode: wrong size buffer")
	}
	s.Int.UnmarshalBinary(buff)
	s.Int.SetLittleEndian(buff)
	return nil
}

func (s *secret) String() string {
	return hex.EncodeToString(s.Int.LittleEndian(32, 32))
}
