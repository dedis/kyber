// Package bdn implements the Boneh-Drijvers-Neven signature scheme which is
// an implementation of the bls package which is robust against rogue public-key attacks. Those
// attacks could allow an attacker to forge a public-key and then make a verifiable
// signature for an aggregation of signatures. It fixes the situation by
// adding coefficients to the aggregate.
//
// See the papers:
// https://eprint.iacr.org/2018/483.pdf
// https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
package bdn

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/mod"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/sign"
	"go.dedis.ch/kyber/v4/sign/bls"
	"golang.org/x/crypto/blake2s"
)

// modulus128 can be provided to the big integer implementation to create numbers
// over 128 bits
var modulus128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

// For the choice of H, we're mostly worried about the second preimage attack. In
// other words, find m' where H(m) == H(m')
// We also use the entire roster so that the coefficient will vary for the same
// public key used in different roster
func hashPointToR(pubs []kyber.Point) ([]kyber.Scalar, error) {
	h, err := blake2s.NewXOF(blake2s.OutputLengthUnknown, nil)
	if err != nil {
		return nil, err
	}
	for _, pub := range pubs {
		peer, err := pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, err = h.Write(peer)
		if err != nil {
			return nil, err
		}
	}

	out := make([]byte, 16*len(pubs))
	_, err = h.Read(out)
	if err != nil {
		return nil, err
	}

	coefs := make([]kyber.Scalar, len(pubs))
	for i := range coefs {
		coefs[i] = mod.NewIntBytes(out[i*16:(i+1)*16], modulus128, kyber.LittleEndian)
	}

	return coefs, nil
}

type Scheme struct {
	blsScheme sign.AggregatableScheme
	sigGroup  kyber.Group
	keyGroup  kyber.Group
	pairing   func(signature, public, hashedPoint kyber.Point) bool
}

// NewSchemeOnG1 returns a sign.Scheme that uses G1 for its signature space and G2
// for its public keys
func NewSchemeOnG1(suite pairing.Suite) *Scheme {
	sigGroup := suite.G1()
	keyGroup := suite.G2()
	pairing := func(public, hashedMsg, sigPoint kyber.Point) bool {
		return suite.ValidatePairing(hashedMsg, public, sigPoint, keyGroup.Point().Base())
	}
	return &Scheme{
		blsScheme: bls.NewSchemeOnG1(suite),
		sigGroup:  sigGroup,
		keyGroup:  keyGroup,
		pairing:   pairing,
	}
}

// NewSchemeOnG2 returns a sign.Scheme that uses G2 for its signature space and
// G1 for its public key
func NewSchemeOnG2(suite pairing.Suite) *Scheme {
	sigGroup := suite.G2()
	keyGroup := suite.G1()
	pairing := func(public, hashedMsg, sigPoint kyber.Point) bool {
		return suite.ValidatePairing(public, hashedMsg, keyGroup.Point().Base(), sigPoint)
	}
	return &Scheme{
		blsScheme: bls.NewSchemeOnG2(suite),
		sigGroup:  sigGroup,
		keyGroup:  keyGroup,
		pairing:   pairing,
	}
}

// NewKeyPair creates a new BLS signing key pair. The private key x is a scalar
// and the public key X is a point on the scheme's key group.
func (scheme *Scheme) NewKeyPair(random cipher.Stream) (kyber.Scalar, kyber.Point) {
	return scheme.blsScheme.NewKeyPair(random)
}

// Sign creates a BLS signature S = x * H(m) on a message m using the private
// key x. The signature S is a point on the scheme's signature group.
func (scheme *Scheme) Sign(x kyber.Scalar, msg []byte) ([]byte, error) {
	return scheme.blsScheme.Sign(x, msg)
}

// Verify checks the given BLS signature S on the message m using the public
// key X by verifying that the equality e(H(m), X) == e(H(m), x*B2) ==
// e(x*H(m), B2) == e(S, B2) holds where e is the pairing operation and B2 is
// the base point from the scheme's key group.
func (scheme *Scheme) Verify(x kyber.Point, msg, sig []byte) error {
	return scheme.blsScheme.Verify(x, msg, sig)
}

// AggregateSignatures aggregates the signatures using a coefficient for each
// one of them where c = H(pk) and H: keyGroup -> R with R = {1, ..., 2^128}
func (scheme *Scheme) AggregateSignatures(sigs [][]byte, mask *Mask) (kyber.Point, error) {
	agg := scheme.sigGroup.Point()
	for i := range mask.publics {
		if enabled, err := mask.GetBit(i); err != nil {
			// this should never happen because of the loop boundary
			// an error here is probably a bug in the mask implementation
			return nil, fmt.Errorf("couldn't find the index %d: %w", i, err)
		} else if !enabled {
			continue
		}

		if len(sigs) == 0 {
			return nil, errors.New("length of signatures and public keys must match")
		}

		buf := sigs[0]
		sigs = sigs[1:]

		sig := scheme.sigGroup.Point()
		err := sig.UnmarshalBinary(buf)
		if err != nil {
			return nil, err
		}

		sigC := sig.Clone().Mul(mask.publicCoefs[i], sig)
		// c+1 because R is in the range [1, 2^128] and not [0, 2^128-1]
		sigC = sigC.Add(sigC, sig)
		agg = agg.Add(agg, sigC)
	}

	if len(sigs) > 0 {
		return nil, errors.New("length of signatures and public keys must match")
	}

	return agg, nil
}

// AggregatePublicKeys aggregates a set of public keys (similarly to
// AggregateSignatures for signatures) using the hash function
// H: keyGroup -> R with R = {1, ..., 2^128}.
func (scheme *Scheme) AggregatePublicKeys(mask *Mask) (kyber.Point, error) {
	agg := scheme.keyGroup.Point()
	for i := range mask.publics {
		if enabled, err := mask.GetBit(i); err != nil {
			// this should never happen because of the loop boundary
			// an error here is probably a bug in the mask implementation
			return nil, fmt.Errorf("couldn't find the index %d: %w", i, err)
		} else if !enabled {
			continue
		}

		agg = agg.Add(agg, mask.publicTerms[i])
	}

	return agg, nil
}

// v1 API Deprecated ----------------------------------

// NewKeyPair creates a new BLS signing key pair. The private key x is a scalar
// and the public key X is a point on curve G2.
// Deprecated: use the new scheme methods instead.
func NewKeyPair(suite pairing.Suite, random cipher.Stream) (kyber.Scalar, kyber.Point) {
	return NewSchemeOnG1(suite).NewKeyPair(random)
}

// Sign creates a BLS signature S = x * H(m) on a message m using the private
// key x. The signature S is a point on curve G1.
// Deprecated: use the new scheme methods instead.
func Sign(suite pairing.Suite, x kyber.Scalar, msg []byte) ([]byte, error) {
	return NewSchemeOnG1(suite).Sign(x, msg)
}

// Verify checks the given BLS signature S on the message m using the public
// key X by verifying that the equality e(H(m), X) == e(H(m), x*B2) ==
// e(x*H(m), B2) == e(S, B2) holds where e is the pairing operation and B2 is
// the base point from curve G2.
// Deprecated: use the new scheme methods instead.
func Verify(suite pairing.Suite, x kyber.Point, msg, sig []byte) error {
	return NewSchemeOnG1(suite).Verify(x, msg, sig)
}

// AggregateSignatures aggregates the signatures using a coefficient for each
// one of them where c = H(pk) and H: G2 -> R with R = {1, ..., 2^128}
// Deprecated: use the new scheme methods instead.
func AggregateSignatures(suite pairing.Suite, sigs [][]byte, mask *Mask) (kyber.Point, error) {
	return NewSchemeOnG1(suite).AggregateSignatures(sigs, mask)
}

// AggregatePublicKeys aggregates a set of public keys (similarly to
// AggregateSignatures for signatures) using the hash function
// H: G2 -> R with R = {1, ..., 2^128}.
// Deprecated: use the new scheme methods instead.
func AggregatePublicKeys(suite pairing.Suite, mask *Mask) (kyber.Point, error) {
	return NewSchemeOnG1(suite).AggregatePublicKeys(mask)
}
