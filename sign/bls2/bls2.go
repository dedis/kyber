// Package bls2 implements the robust BLS scheme that prevents rogue public-key
// to be used to forge signatures
// See the paper: https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
package bls2

import (
	"crypto/cipher"
	"crypto/md5"
	"errors"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
)

var modulus128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

// For the choice of H, we're mostly worried about the second preimage attack. In
// other words, find H(m) == H(m')
func hashPointToR(point kyber.Point) (kyber.Scalar, error) {
	h := md5.New()

	buf, err := point.MarshalBinary()
	if err != nil {
		return nil, err
	}

	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}

	r := mod.NewIntBytes(buf, modulus128, mod.LittleEndian)
	return r, nil
}

// NewKeyPair creates a new BLS signing key pair. The private key x is a scalar
// and the public key X is a point on curve G2.
func NewKeyPair(suite pairing.Suite, random cipher.Stream) (kyber.Scalar, kyber.Point) {
	return bls.NewKeyPair(suite, random)
}

// Sign creates a BLS signature S = x * H(m) on a message m using the private
// key x. The signature S is a point on curve G1.
func Sign(suite pairing.Suite, x kyber.Scalar, msg []byte) ([]byte, error) {
	return bls.Sign(suite, x, msg)
}

// Verify checks the given BLS signature S on the message m using the public
// key X by verifying that the equality e(H(m), X) == e(H(m), x*B2) ==
// e(x*H(m), B2) == e(S, B2) holds where e is the pairing operation and B2 is
// the base point from curve G2.
func Verify(suite pairing.Suite, x kyber.Point, msg, sig []byte) error {
	return bls.Verify(suite, x, msg, sig)
}

// AggregateSignatures aggregates the signatures using a coefficient for each
// one of them where c = H(pk) and H: G2 -> R{1, ..., 2^128}
func AggregateSignatures(suite pairing.Suite, sigs [][]byte, pubs []kyber.Point) (kyber.Point, error) {
	if len(sigs) != len(pubs) {
		return nil, errors.New("length of signatures and public keys must match")
	}

	agg := suite.G1().Point()
	for i, buf := range sigs {
		c, err := hashPointToR(pubs[i])
		if err != nil {
			return nil, err
		}

		sig := suite.G1().Point()
		err = sig.UnmarshalBinary(buf)
		if err != nil {
			return nil, err
		}

		sigC := sig.Clone().Mul(c, sig)
		// c+1 because R is in the range [1, 2^128] and not [0, 2^128-1]
		sigC = sigC.Add(sigC, sig)
		agg = agg.Add(agg, sigC)
	}

	return agg, nil
}

// AggregatePublicKeys aggregates the same way as for the signatures using
// the same H: G2 -> R{1, ..., 2^128} as the hash function.
func AggregatePublicKeys(pubs []kyber.Point) (kyber.Point, error) {
	agg := pubs[0].Clone().Null()
	for _, pub := range pubs {
		c, err := hashPointToR(pub)
		if err != nil {
			return nil, err
		}

		pubC := pub.Clone().Mul(c, pub)
		pubC = pubC.Add(pubC, pub)
		agg = agg.Add(agg, pubC)
	}

	return agg, nil
}
