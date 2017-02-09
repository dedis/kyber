package sign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
)

// Schnorr creates a Schnorr signature from a msg and a private key. This
// signature can be verified with VerifySchnorr. It's also a valid EdDSA
// signature.
func Schnorr(suite abstract.Suite, private abstract.Scalar, msg []byte) ([]byte, error) {
	// using notation from https://en.wikipedia.org/wiki/Schnorr_signature
	// create random secret k and public point commitment r
	k := suite.Scalar().Pick(random.Stream)
	r := suite.Point().Mul(nil, k)

	// create challenge e based on message and r
	public := suite.Point().Mul(nil, private)
	e, err := hash(suite, public, r, msg)
	if err != nil {
		return nil, err
	}

	// compute response s = k - x*e
	xe := suite.Scalar().Mul(private, e)
	s := suite.Scalar().Sub(k, xe)

	var b bytes.Buffer
	if _, err := e.MarshalTo(&b); err != nil {
		return nil, err
	}
	if _, err := s.MarshalTo(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// VerifySchnorr verifies a given Schnorr signature. It returns nil iff the
// given signature is valid.  NOTE: this signature scheme is malleable because
// the response's unmarshalling is done directly into a big.Int modulo (see
// nist.Int).
func VerifySchnorr(suite abstract.Suite, public abstract.Point, msg, sig []byte) error {
	challenge := suite.Scalar()
	response := suite.Scalar()
	scalarSize := challenge.MarshalSize()
	sigSize := scalarSize * 2
	if len(sig) != sigSize {
		return fmt.Errorf("schnorr: signature of invalid length %d instead of %d", len(sig), sigSize)
	}
	if err := challenge.UnmarshalBinary(sig[:scalarSize]); err != nil {
		return err
	}
	if err := response.UnmarshalBinary(sig[scalarSize:]); err != nil {
		return err
	}
	// compute rv = g^s * y^e (where y = g^x)
	gs := suite.Point().Mul(nil, response)
	ye := suite.Point().Mul(public, challenge)
	rv := suite.Point().Add(gs, ye)

	// recompute challenge (e) from rv
	e, err := hash(suite, public, rv, msg)
	if err != nil {
		return err
	}

	if !e.Equal(challenge) {
		return errors.New("schnorr: invalid signature")
	}

	return nil
}

func hash(suite abstract.Suite, public, r abstract.Point, msg []byte) (abstract.Scalar, error) {
	h := suite.Hash()
	if _, err := r.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := public.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return suite.Scalar().SetBytes(h.Sum(nil)), nil
}
