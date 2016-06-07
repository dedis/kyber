package ed25519

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
)

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
	sec := a.(*ed25519Secret)
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

// EdDSAVerify verifies a signature issued by EdDSASign
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
