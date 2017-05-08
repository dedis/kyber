package sign

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/util/random"
)

// Schnorr creates a Schnorr signature from a msg and a private key. This
// signature can be verified with VerifySchnorr. It's also a valid EdDSA
// signature.
func Schnorr(g crypto.Group, private crypto.Scalar, msg []byte) ([]byte, error) {
	// create random secret k and public point commitment R
	k := g.Scalar().Pick(random.Stream)
	R := g.Point().Mul(nil, k)

	// create hash(public || R || message)
	public := g.Point().Mul(nil, private)
	h, err := hash(g, public, R, msg)
	if err != nil {
		return nil, err
	}

	// compute response s = k + x*h
	xh := g.Scalar().Mul(private, h)
	s := g.Scalar().Add(k, xh)

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
// given signature is valid.  NOTE XXX TODO: this signature scheme is malleable because
// the response's unmarshalling is done directly into a big.Int modulo (see
// nist.Int).
func VerifySchnorr(g crypto.Group, public crypto.Point, msg, sig []byte) error {
	R := g.Point()
	s := g.Scalar()
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
	h, err := hash(g, public, R, msg)
	if err != nil {
		return err
	}

	// compute S = g^s
	S := g.Point().Mul(nil, s)
	// compute RAh = R + A^h
	Ah := g.Point().Mul(public, h)
	RAs := g.Point().Add(R, Ah)

	if !S.Equal(RAs) {
		return errors.New("schnorr: invalid signature")
	}

	return nil
}

func hash(g crypto.Group, public, r crypto.Point, msg []byte) (crypto.Scalar, error) {
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
