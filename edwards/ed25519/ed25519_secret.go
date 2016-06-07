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

type ed25519Secret struct {
	*nist.Int
	prefix []byte
}

func newSecret() *ed25519Secret {
	return &ed25519Secret{
		Int: nist.NewInt(0, &primeOrder.V),
	}
}

func newSecretFromInt64(v int64) *ed25519Secret {
	return &ed25519Secret{
		Int: nist.NewInt(v, &primeOrder.V),
	}
}

func newSecretFromString(str string, b int) *ed25519Secret {
	i, _ := new(nist.Int).SetString(str, "", b)
	return &ed25519Secret{
		Int: i,
	}
}

func newSecretFromBytes(buff []byte) *ed25519Secret {
	s := newSecret()
	s.SetLittleEndian(buff)
	return s
}

func (e *ed25519Secret) Equal(s2 abstract.Secret) bool {
	return e.Int.Equal(s2.(*ed25519Secret).Int)
}

func (e *ed25519Secret) Set(a abstract.Secret) abstract.Secret {
	e.Int.Set(a.(*ed25519Secret).Int)
	return e
}
func (e *ed25519Secret) SetInt64(v int64) abstract.Secret {
	e.Int.SetInt64(v)
	return e
}

func (e *ed25519Secret) Zero() abstract.Secret {
	e.Int.Zero()
	return e
}

func (e *ed25519Secret) Add(a, b abstract.Secret) abstract.Secret {
	e.Int.Add(a.(*ed25519Secret).Int, b.(*ed25519Secret).Int)
	return e
}

func (e *ed25519Secret) Sub(a, b abstract.Secret) abstract.Secret {
	e.Int.Sub(a.(*ed25519Secret).Int, b.(*ed25519Secret).Int)
	return e
}

func (e *ed25519Secret) Neg(a abstract.Secret) abstract.Secret {
	e.Int.Neg(a.(*ed25519Secret).Int)
	return e
}

func (e *ed25519Secret) One() abstract.Secret {
	e.Int.One()
	return e
}

func (e *ed25519Secret) Mul(a, b abstract.Secret) abstract.Secret {
	e.Int.Mul(a.(*ed25519Secret).Int, b.(*ed25519Secret).Int)
	return e
}

func (e *ed25519Secret) Div(a, b abstract.Secret) abstract.Secret {
	e.Int.Div(a.(*ed25519Secret).Int, b.(*ed25519Secret).Int)
	return e
}

func (e *ed25519Secret) Inv(a abstract.Secret) abstract.Secret {
	e.Int.Inv(a.(*ed25519Secret).Int)
	return e
}

func (e *ed25519Secret) Pick(rand cipher.Stream) abstract.Secret {
	pre := random.Bytes(32, rand)
	expandedSecretKey := sha512.Sum512(pre)
	expandedSecretKey[0] &= 0xf8
	expandedSecretKey[31] &= 0x3f
	expandedSecretKey[31] |= 0x40

	e.Int.SetLittleEndian(expandedSecretKey[:32])
	// let's keep the prefix if we want to do a EdDSA signing scheme
	e.prefix = expandedSecretKey[32:]
	return e
}

func (e *ed25519Secret) MarshalBinary() ([]byte, error) {
	return e.Int.LittleEndian(32, 32), nil
}

func (e *ed25519Secret) UnmarshalBinary(buff []byte) error {
	if len(buff) != e.MarshalSize() {
		return errors.New("Int.Decode: wrong size buffer")
	}
	e.Int.SetLittleEndian(buff)
	return nil
}

func (e *ed25519Secret) String() string {
	return hex.EncodeToString(e.Int.LittleEndian(32, 32))
}

func (e *ed25519Secret) setString(str, d string, base int) (*ed25519Secret, bool) {
	_, b := e.Int.SetString(str, d, base)
	return e, b
}
