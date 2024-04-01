// Package eddsa implements the EdDSA signature algorithm according to
// RFC8032.
package eddsa

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var group = new(edwards25519.Curve)

// EdDSA is a structure holding the data necessary to make a series of
// EdDSA signatures.
type EdDSA struct {
	// Secret being already hashed + bit tweaked
	Secret kyber.Scalar
	// Public is the corresponding public key
	Public kyber.Point

	seed   []byte
	prefix []byte
}

// NewEdDSA will return a freshly generated key pair to use for generating
// EdDSA signatures.
func NewEdDSA(stream cipher.Stream) *EdDSA {
	if stream == nil {
		panic("stream is required")
	}

	secret, buffer, prefix := group.NewKeyAndSeed(stream)
	public := group.Point().Mul(secret, nil)

	return &EdDSA{
		seed:   buffer,
		prefix: prefix,
		Secret: secret,
		Public: public,
	}
}

// MarshalBinary will return the representation used by the reference
// implementation of SUPERCOP ref10, which is "seed || Public".
func (e *EdDSA) MarshalBinary() ([]byte, error) {
	pBuff, err := e.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}

	eddsa := make([]byte, 64)
	copy(eddsa, e.seed)
	copy(eddsa[32:], pBuff)
	return eddsa, nil
}

// UnmarshalBinary transforms a slice of bytes into a EdDSA signature.
func (e *EdDSA) UnmarshalBinary(buff []byte) error {
	if len(buff) != 64 {
		return errors.New("wrong length for decoding EdDSA private")
	}

	secret, _, prefix := group.NewKeyAndSeedWithInput(buff[:32])

	e.seed = buff[:32]
	e.prefix = prefix
	e.Secret = secret
	e.Public = group.Point().Mul(e.Secret, nil)
	return nil
}

// Sign will return a EdDSA signature of the message msg using Ed25519.
func (e *EdDSA) Sign(msg []byte) ([]byte, error) {
	hash := sha512.New()
	_, _ = hash.Write(e.prefix)
	_, _ = hash.Write(msg)

	// deterministic random secret and its commit
	r := group.Scalar().SetBytes(hash.Sum(nil))
	R := group.Point().Mul(r, nil)

	// challenge
	// H( R || Public || Msg)
	hash.Reset()
	Rbuff, err := R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	Abuff, err := e.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}

	_, _ = hash.Write(Rbuff)
	_, _ = hash.Write(Abuff)
	_, _ = hash.Write(msg)

	h := group.Scalar().SetBytes(hash.Sum(nil))

	// response
	// s = r + h * s
	s := group.Scalar().Mul(e.Secret, h)
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

// VerifyWithChecks uses a public key buffer, a message and a signature.
// It will return nil if sig is a valid signature for msg created by
// key public, or an error otherwise. Compared to `Verify`, it performs
// additional checks around the canonicality and ensures the public key
// does not have a small order.
func VerifyWithChecks(pub, msg, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("signature length invalid, expect 64 but got %v", len(sig))
	}

	type scalarCanCheckCanonical interface {
		IsCanonical(b []byte) bool
	}

	if !group.Scalar().(scalarCanCheckCanonical).IsCanonical(sig[32:]) {
		return fmt.Errorf("signature is not canonical")
	}

	type pointCanCheckCanonicalAndSmallOrder interface {
		HasSmallOrder() bool
		IsCanonical(b []byte) bool
	}

	R := group.Point()
	if !R.(pointCanCheckCanonicalAndSmallOrder).IsCanonical(sig[:32]) {
		return fmt.Errorf("R is not canonical")
	}
	if err := R.UnmarshalBinary(sig[:32]); err != nil {
		return fmt.Errorf("got R invalid point: %s", err)
	}
	if R.(pointCanCheckCanonicalAndSmallOrder).HasSmallOrder() {
		return fmt.Errorf("R has small order")
	}

	s := group.Scalar()
	if err := s.UnmarshalBinary(sig[32:]); err != nil {
		return fmt.Errorf("schnorr: s invalid scalar %s", err)
	}

	public := group.Point()
	if !public.(pointCanCheckCanonicalAndSmallOrder).IsCanonical(pub) {
		return fmt.Errorf("public key is not canonical")
	}
	if err := public.UnmarshalBinary(pub); err != nil {
		return fmt.Errorf("invalid public key: %s", err)
	}
	if public.(pointCanCheckCanonicalAndSmallOrder).HasSmallOrder() {
		return fmt.Errorf("public key has small order")
	}

	// reconstruct h = H(R || Public || Msg)
	hash := sha512.New()
	_, _ = hash.Write(sig[:32])
	_, _ = hash.Write(pub)
	_, _ = hash.Write(msg)

	h := group.Scalar().SetBytes(hash.Sum(nil))
	// reconstruct S == k*A + R
	S := group.Point().Mul(s, nil)
	hA := group.Point().Mul(h, public)
	RhA := group.Point().Add(R, hA)

	if !RhA.Equal(S) {
		return errors.New("reconstructed S is not equal to signature")
	}
	return nil
}

// Verify uses a public key, a message and a signature. It will return nil if
// sig is a valid signature for msg created by key public, or an error otherwise.
func Verify(public kyber.Point, msg, sig []byte) error {
	PBuf, err := public.MarshalBinary()
	if err != nil {
		return fmt.Errorf("error unmarshalling public key: %s", err)
	}
	return VerifyWithChecks(PBuf, msg, sig)
}
