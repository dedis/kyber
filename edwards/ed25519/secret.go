package ed25519

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

type secret struct {
	*nist.Int
	prefix []byte
}

func newSecret() *secret {
	/* base := big.NewInt(2)*/
	//exp := big.NewInt(255)
	//modulo := big.NewInt(0).Exp(base, exp, nil)
	//modulo.Sub(modulo, big.NewInt(19))

	return &secret{
		Int: nist.NewInt(0, &primeOrder.Int.V),
		//Int: nist.NewInt(0, modulo),
	}
}

func newSecretFromInt64(v int64) *secret {
	return &secret{
		Int: nist.NewInt(v, &primeOrder.Int.V),
	}
}

func newSecretFromString(str string, b int) *secret {
	i, _ := new(nist.Int).SetString(str, "", b)
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

	/* base := big.NewInt(2)*/
	//exp := big.NewInt(256)
	//modulo := big.NewInt(0).Exp(base, exp, nil)
	//modulo.Sub(modulo, big.NewInt(1))
	//secPruned := nist.NewInt(0, modulo)
	//secPruned.SetLittleEndian(expandedSecretKey[:32])
	/*s.Int = secPruned*/

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

// EdDSASign will return a EdDSA signature using Ed25519. The secret must be
// Picked() so it can use the prefix, the right part of the hashing done in
// Pick.
// Takes
// - suite is the suite to use
// - a secret to use to sign the message
// - A corresponding public key
// - msg message to sign
// NOTE: Code taken from the Python implementation from the RFC
// https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
func EdDSASign(suite abstract.Suite, a abstract.Secret, A abstract.Point, msg []byte) ([]byte, error) {
	sec := a.(*secret)
	hash := sha512.New()
	hash.Write(sec.prefix)
	hash.Write(msg)

	// deterministic random secret and its commit
	r := newSecretFromBytes(hash.Sum(nil))
	R := suite.Point().Mul(nil, r)

	// challenge
	// H( R || Public || Msg)
	hash.Reset()
	Rbuff, err := R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	Abuff, err := A.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hash.Write(Rbuff)
	hash.Write(Abuff)
	hash.Write(msg)

	h := newSecretFromBytes(hash.Sum(nil))

	// response
	// s = r + h * secret
	s := suite.Secret().Mul(a, h)
	s.Add(r, s)

	sBuff, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// return R || s
	var sig [64]byte
	copy(sig[:], Rbuff)
	copy(sig[32:], sBuff)

	return sig[:], nil
}

// EdDSAVerify verify a signature issued by EdDSASign
// Takes:
//  - suite to use
//  - public key used in signing
//  - msg is the message to sign
//  - sig is the signature return by EdDSASign
// Returns an error on failure and nil on success
func EdDSAVerify(suite abstract.Suite, public abstract.Point, msg, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("Signature length invalid")
	}

	R := suite.Point()
	if err := R.UnmarshalBinary(sig[:32]); err != nil {
		return fmt.Errorf("R invalid point: %s", err)
	}

	s := suite.Secret()
	s.UnmarshalBinary(sig[32:])

	// reconstruct h = H(R || Public || Msg)
	Pbuff, err := public.MarshalBinary()
	if err != nil {
		return err
	}
	hash := sha512.New()
	hash.Write(sig[:32])
	hash.Write(Pbuff)
	hash.Write(msg)

	h := newSecretFromBytes(hash.Sum(nil))
	// reconstruct S == k*A + R
	S := suite.Point().Mul(nil, s)
	hA := suite.Point().Mul(public, h)
	RhA := suite.Point().Add(R, hA)

	if !RhA.Equal(S) {
		return errors.New("Recontructed S is not equal to signature")
	}
	return nil
}
