// Package eddsa implements the EdDSA signature algorithm according to
// RFC8032.
package eddsa

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var group = new(edwards25519.Curve)

// TODO: maybe export prime and primeOrder from edwards25519/const or allow it to be
// retrieved from the curve?
var prime, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
var primeOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

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

// edDSAPoint is used to verify signatures
// with checks around canonicality and group order
type edDSAPoint interface {
	kyber.Point
	// HasSmallOrder checks if the given buffer (in little endian)
	// represents a point with a small order
	HasSmallOrder() bool
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
	if !scalarIsCanonical(sig[32:]) {
		return fmt.Errorf("signature is not canonical")
	}
	if !pointIsCanonical(pub) {
		return fmt.Errorf("public key is not canonical")
	}

	if !pointIsCanonical(sig[:32]) {
		return fmt.Errorf("R is not canonical")
	}
	R := group.Point()
	if err := R.UnmarshalBinary(sig[:32]); err != nil {
		return fmt.Errorf("got R invalid point: %s", err)
	}
	if R.(edDSAPoint).HasSmallOrder() {
		return fmt.Errorf("R has small order")
	}

	s := group.Scalar()
	if err := s.UnmarshalBinary(sig[32:]); err != nil {
		return fmt.Errorf("schnorr: s invalid scalar %s", err)
	}

	public := group.Point()
	if err := public.UnmarshalBinary(pub); err != nil {
		return fmt.Errorf("invalid public key: %s", err)
	}
	if public.(edDSAPoint).HasSmallOrder() {
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

// scalarIsCanonical whether scalar s is in the range 0<=s<L as required by RFC8032, Section 5.1.7.
// Also provides Strong Unforgeability under Chosen Message Attacks (SUF-CMA)
// See paper https://eprint.iacr.org/2020/823.pdf for definitions and theorems
// See https://github.com/jedisct1/libsodium/blob/4744636721d2e420f8bbe2d563f31b1f5e682229/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L2568
// for a reference
func scalarIsCanonical(sb []byte) bool {
	if len(sb) != 32 {
		return false
	}

	if sb[31]&0xf0 == 0 {
		return true
	}

	L := primeOrder.Bytes()
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		L[i], L[j] = L[j], L[i]
	}

	var c byte
	var n byte = 1

	for i := 31; i >= 0; i-- {
		// subtraction might lead to an underflow which needs
		// to be accounted for in the right shift
		c |= byte((uint16(sb[i])-uint16(L[i]))>>8) & n
		n &= byte((uint16(sb[i]) ^ uint16(L[i]) - 1) >> 8)
	}

	return c != 0
}

// pointIsCanonical determines whether the group element is canonical
//
// Checks whether group element s is less than p, according to RFC8032§5.1.3.1
// https://tools.ietf.org/html/rfc8032#section-5.1.3
//
// Taken from
// https://github.com/jedisct1/libsodium/blob/4744636721d2e420f8bbe2d563f31b1f5e682229/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1113
func pointIsCanonical(s []byte) bool {
	if len(s) != 32 {
		return false
	}

	c := (s[31] & 0x7f) ^ 0x7f
	for i := 30; i > 0; i-- {
		c |= s[i] ^ 0xff
	}

	// subtraction might underflow
	c = byte((uint16(c) - 1) >> 8)
	d := byte((0xed - 1 - uint16(s[0])) >> 8)

	return 1-(c&d&1) == 1
}
