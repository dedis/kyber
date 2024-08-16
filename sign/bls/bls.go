// Package bls implements the Boneh-Lynn-Shacham (BLS) signature scheme which
// was introduced in the paper "Short Signatures from the Weil Pairing". BLS
// requires pairing-based cryptography.
//
// This version is vulnerable to rogue public-key attack and the
// new version of the protocol should be used to make sure a signature
// aggregate cannot be verified by a forged key. You can find the protocol
// in kyber/sign/bdn. Note that only the aggregation is broken against the
// attack and a later version will merge bls and asmbls.
//
// See the paper: https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
package bls

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/sign"
)

type scheme struct {
	sigGroup kyber.Group
	keyGroup kyber.Group
	pairing  func(signature, public, hashedPoint kyber.Point) bool
}

// NewSchemeOnG1 returns a sign.Scheme that uses G1 for its signature space and G2
// for its public keys
func NewSchemeOnG1(suite pairing.Suite) sign.Scheme {
	sigGroup := suite.G1()
	keyGroup := suite.G2()
	pairing := func(public, hashedMsg, sigPoint kyber.Point) bool {
		return suite.ValidatePairing(hashedMsg, public, sigPoint, keyGroup.Point().Base())
	}
	return &scheme{
		sigGroup: sigGroup,
		keyGroup: keyGroup,
		pairing:  pairing,
	}
}

// NewSchemeOnG2 returns a sign.Scheme that uses G2 for its signature space and
// G1 for its public key
func NewSchemeOnG2(suite pairing.Suite) sign.Scheme {
	sigGroup := suite.G2()
	keyGroup := suite.G1()
	pairing := func(public, hashedMsg, sigPoint kyber.Point) bool {
		return suite.ValidatePairing(public, hashedMsg, keyGroup.Point().Base(), sigPoint)
	}
	return &scheme{
		sigGroup: sigGroup,
		keyGroup: keyGroup,
		pairing:  pairing,
	}
}

func (s *scheme) NewKeyPair(random cipher.Stream) (kyber.Scalar, kyber.Point) {
	secret := s.keyGroup.Scalar().Pick(random)
	public := s.keyGroup.Point().Mul(secret, nil)
	return secret, public
}

func (s *scheme) Sign(private kyber.Scalar, msg []byte) ([]byte, error) {
	hashable, ok := s.sigGroup.Point().(kyber.HashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}
	HM := hashable.Hash(msg)
	xHM := HM.Mul(private, HM)

	sig, err := xHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *scheme) Verify(X kyber.Point, msg, sig []byte) error {
	hashable, ok := s.sigGroup.Point().(kyber.HashablePoint)
	if !ok {
		return errors.New("bls: point needs to implement hashablePoint")
	}
	HM := hashable.Hash(msg)
	sigPoint := s.sigGroup.Point()
	if err := sigPoint.UnmarshalBinary(sig); err != nil {
		return err
	}
	if !s.pairing(X, HM, sigPoint) {
		return errors.New("bls: invalid signature")
	}
	return nil
}

func distinct(msgs [][]byte) bool {
	m := make(map[[32]byte]bool)
	for _, msg := range msgs {
		h := sha256.Sum256(msg)
		if m[h] {
			return false
		}
		m[h] = true
	}
	return true
}
