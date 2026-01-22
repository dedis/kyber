// Package eddsa implements the EdDSA signature algorithm according to
// RFC8032.
package eddsa

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

var group = new(edwards25519.Curve)
var ErrPKMarshalling = errors.New("error unmarshalling public key")
var ErrPKInvalid = errors.New("invalid public key")
var ErrPKSmallOrder = errors.New("public key has small order")
var ErrPKNotCanonical = errors.New("public key is not canonical")

var ErrEdDSAWrongLength = errors.New("wrong length for decoding EdDSA private")
var ErrSchnorrInvalidScalar = errors.New("schnorr: s invalid scalar")
var ErrSignatureLength = errors.New("signature length invalid")
var ErrSignatureNotCanonical = errors.New("signature is not canonical")
var ErrSignatureRecNotEqual = errors.New("reconstructed S is not equal to signature")

var ErrPointRSmallOrder = errors.New("point R has small order")
var ErrPointRNotCanonical = errors.New("point R is not canonical")
var ErrPointRInvalid = errors.New("point R invalid")

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
		return fmt.Errorf("error: %w", ErrEdDSAWrongLength)
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
	if _, err := hash.Write(e.prefix); err != nil {
		return nil, err
	}
	if _, err := hash.Write(msg); err != nil {
		return nil, err
	}

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

	if _, err := hash.Write(Rbuff); err != nil {
		return nil, err
	}
	if _, err := hash.Write(Abuff); err != nil {
		return nil, err
	}
	if _, err := hash.Write(msg); err != nil {
		return nil, err
	}

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
		return fmt.Errorf("error: %w: expect 64 but got %v", ErrSignatureLength, len(sig))
	}

	type scalarCanCheckCanonical interface {
		IsCanonical(b []byte) bool
	}

	scalarCanonical, ok := group.Scalar().(scalarCanCheckCanonical)
	if !ok {
		return errors.New("could not cast group scalar to canonical")
	}
	if !scalarCanonical.IsCanonical(sig[32:]) {
		return fmt.Errorf("error: %w", ErrSignatureNotCanonical)
	}

	type pointCanCheckCanonicalAndSmallOrder interface {
		HasSmallOrder() bool
		IsCanonical(b []byte) bool
	}

	R := group.Point()
	RCastToPoint, ok := R.(pointCanCheckCanonicalAndSmallOrder)
	if !ok {
		return ErrPointRInvalid
	}

	if !RCastToPoint.IsCanonical(sig[:32]) {
		return fmt.Errorf("error: %w", ErrPointRNotCanonical)
	}
	if err := R.UnmarshalBinary(sig[:32]); err != nil {
		return fmt.Errorf("error: %w: %w", ErrPointRInvalid, err)
	}
	if RCastToPoint.HasSmallOrder() {
		return fmt.Errorf("error: %w", ErrPointRSmallOrder)
	}

	s := group.Scalar()
	if err := s.UnmarshalBinary(sig[32:]); err != nil {
		return fmt.Errorf("error: %w: %w", ErrSchnorrInvalidScalar, err)
	}

	public := group.Point()
	publicCastToPoint, ok := public.(pointCanCheckCanonicalAndSmallOrder)
	if !ok {
		return ErrPKInvalid
	}
	if !publicCastToPoint.IsCanonical(pub) {
		return fmt.Errorf("error: %w", ErrPKNotCanonical)
	}
	if err := public.UnmarshalBinary(pub); err != nil {
		return fmt.Errorf("error: %w: %w", ErrPKInvalid, err)
	}
	if publicCastToPoint.HasSmallOrder() {
		return fmt.Errorf("error: %w", ErrPKSmallOrder)
	}

	// reconstruct h = H(R || Public || Msg)
	hash := sha512.New()
	if _, err := hash.Write(sig[:32]); err != nil {
		return err
	}
	if _, err := hash.Write(pub); err != nil {
		return err
	}
	if _, err := hash.Write(msg); err != nil {
		return err
	}

	h := group.Scalar().SetBytes(hash.Sum(nil))
	// reconstruct S == k*A + R
	S := group.Point().Mul(s, nil)
	hA := group.Point().Mul(h, public)
	RhA := group.Point().Add(R, hA)

	if !RhA.Equal(S) {
		return fmt.Errorf("error: %w", ErrSignatureRecNotEqual)
	}
	return nil
}

// Verify uses a public key, a message and a signature. It will return nil if
// sig is a valid signature for msg created by key public, or an error otherwise.
func Verify(public kyber.Point, msg, sig []byte) error {
	PBuf, err := public.MarshalBinary()
	if err != nil {
		return fmt.Errorf("error: %w: %w", ErrPKMarshalling, err)
	}
	return VerifyWithChecks(PBuf, msg, sig)
}
