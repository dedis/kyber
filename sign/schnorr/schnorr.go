/*
Package schnorr implements the vanilla Schnorr signature scheme.
See https://en.wikipedia.org/wiki/Schnorr_signature.

The only difference regarding the vanilla reference is the computation of
the response. This implementation adds the random component with the
challenge times private key while the Wikipedia article substracts them.

The resulting signature is compatible with EdDSA verification algorithm
when using the edwards25519 group, and by extension the CoSi verification algorithm.
*/
package schnorr

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// Suite represents the set of functionalities needed by the package schnorr.
type Suite interface {
	kyber.Group
	kyber.Random
}

// Sign creates a Sign signature from a msg and a private key. This
// signature can be verified with VerifySchnorr. It's also a valid EdDSA
// signature when using the edwards25519 Group.
func Sign(s Suite, private kyber.Scalar, msg []byte) ([]byte, error) {
	var g kyber.Group = s
	// create random secret k and public point commitment R
	k := g.Scalar().Pick(s.RandomStream())
	R := g.Point().Mul(k, nil)

	// create hash(public || R || message)
	public := g.Point().Mul(private, nil)
	h, err := hash(g, public, R, msg)
	if err != nil {
		return nil, err
	}

	// compute response s = k + x*h
	xh := g.Scalar().Mul(private, h)
	S := g.Scalar().Add(k, xh)

	// return R || s
	var b bytes.Buffer
	if _, err := R.MarshalTo(&b); err != nil {
		return nil, err
	}
	if _, err := S.MarshalTo(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// VerifyWithChecks uses a public key buffer, a message and a signature.
// It will return nil if sig is a valid signature for msg created by
// key public, or an error otherwise. Compared to `Verify`, it performs
// additional checks around the canonicality and ensures the public key
// does not have a small order, only when using the ed25519 curve.
func VerifyWithChecks(g kyber.Group, pub, msg, sig []byte) error {
	R := g.Point()
	s := g.Scalar()
	pointSize := R.MarshalSize()
	scalarSize := s.MarshalSize()
	sigSize := scalarSize + pointSize
	if len(sig) != sigSize {
		return fmt.Errorf("schnorr: signature of invalid length %d instead of %d", len(sig), sigSize)
	}

	if _, is25519 := s.(kyber.Ed25519Scalar); is25519 {
		if len(sig) != 64 {
			return fmt.Errorf("signature length invalid, expect 64 but got %v", len(sig))
		}
		// The goal of the first comparison is to prevent calling function scalarIsCanonical()
		// in 99.999% of the cases, saving CPU cycles: this function is called if and only if any
		// of the most significant 4 bits of sig[32:] are set
		if (sig[63]&240) > 0 && !edwards25519.ScalarIsCanonical(sig[32:]) {
			return fmt.Errorf("signature is not canonical")
		}
		if !edwards25519.PointIsCanonical(pub) {
			return fmt.Errorf("public key is not canonical")
		}
	}

	if err := R.UnmarshalBinary(sig[:pointSize]); err != nil {
		return err
	}
	if err := s.UnmarshalBinary(sig[pointSize:]); err != nil {
		return err
	}
	public := g.Point()
	if err := public.UnmarshalBinary(pub); err != nil {
		return fmt.Errorf("invalid public key: %s", err)
	}

	if REd25519, is25519 := R.(kyber.Ed25519Point); is25519 {
		if !edwards25519.PointIsCanonical(sig[:32]) {
			return fmt.Errorf("R is not canonical")
		}
		if REd25519.HasSmallOrder() {
			return fmt.Errorf("R has small order")
		}
		if public.(kyber.Ed25519Point).HasSmallOrder() {
			return fmt.Errorf("public key has small order")
		}
	}

	// recompute hash(public || R || msg)
	h, err := hash(g, public, R, msg)
	if err != nil {
		return err
	}

	// compute S = g^s
	S := g.Point().Mul(s, nil)
	// compute RAh = R + A^h
	Ah := g.Point().Mul(h, public)
	RAs := g.Point().Add(R, Ah)

	if !S.Equal(RAs) {
		return errors.New("schnorr: invalid signature")
	}

	return nil
}

// Verify uses a public key, a message and a Schnorr signature. It will return nil if
// sig is a valid signature for msg created by key public, or an error otherwise.
func Verify(g kyber.Group, public kyber.Point, msg, sig []byte) error {
	PBuf, err := public.MarshalBinary()
	if err != nil {
		return fmt.Errorf("error unmarshalling public key: %s", err)
	}
	return VerifyWithChecks(g, PBuf, msg, sig)
}

func hash(g kyber.Group, public, r kyber.Point, msg []byte) (kyber.Scalar, error) {
	h := sha512.New()
	if _, err := r.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := public.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return g.Scalar().SetBytes(h.Sum(nil)), nil
}
