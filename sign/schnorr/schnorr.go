package sign

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
)

// Schnorr creates a Schnorr signature from a msg and a private key. This
// signature can be verified with VerifySchnorr. It's also a valid EdDSA
// signature.
func Schnorr(suite kyber.Suite, private kyber.Scalar, msg []byte) ([]byte, error) {
	// create random secret k and public point commitment R
	k := suite.Scalar().Pick(random.Stream)
	R := suite.Point().Mul(nil, k)

	// create hash(public || R || message)
	public := suite.Point().Mul(nil, private)
	h, err := hash(suite, public, R, msg)
	if err != nil {
		return nil, err
	}

	// compute response s = k + x*h
	xh := suite.Scalar().Mul(private, h)
	s := suite.Scalar().Add(k, xh)

	// return R || s
	var b bytes.Buffer
	if _, err := R.MarshalTo(&b); err != nil {
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
func VerifySchnorr(suite kyber.Suite, public kyber.Point, msg, sig []byte) error {
	R := suite.Point()
	s := suite.Scalar()
	pointSize := R.MarshalSize()
	scalarSize := s.MarshalSize()
	sigSize := scalarSize + pointSize
	if len(sig) != sigSize {
		return fmt.Errorf("schnorr: signature of invalid length %d instead of %d", len(sig), sigSize)
	}
	if err := R.UnmarshalBinary(sig[:pointSize]); err != nil {
		return err
	}
	if err := s.UnmarshalBinary(sig[pointSize:]); err != nil {
		return err
	}
	// recompute hash(public || R || msg)
	h, err := hash(suite, public, R, msg)
	if err != nil {
		return err
	}

	// compute S = g^s
	S := suite.Point().Mul(nil, s)
	// compute RAh = R + A^h
	Ah := suite.Point().Mul(public, h)
	RAs := suite.Point().Add(R, Ah)

	if !S.Equal(RAs) {
		return errors.New("schnorr: invalid signature")
	}

	return nil
}

func hash(suite kyber.Suite, public, r kyber.Point, msg []byte) (kyber.Scalar, error) {
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
	return suite.Scalar().SetBytes(h.Sum(nil)), nil
}
