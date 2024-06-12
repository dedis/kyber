// Package pvss implements public verifiable secret sharing as introduced in
// "A Simple Publicly Verifiable Secret Sharing Scheme and its Application to
// Electronic Voting" by Berry Schoenmakers. In comparison to regular verifiable
// secret sharing schemes, PVSS enables any third party to verify shares
// distributed by a dealer using zero-knowledge proofs. PVSS runs in three steps:
//  1. The dealer creates a list of encrypted public verifiable shares using
//     EncShares() and distributes them to the trustees.
//  2. Upon the announcement that the secret should be released, each trustee
//     uses DecShare() to first verify and, if valid, decrypt his share.
//  3. Once a threshold of decrypted shares has been released, anyone can
//     verify them and, if enough shares are valid, recover the shared secret
//     using RecoverSecret().
package pvss

import (
	"errors"
	"math/big"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/proof/dleq"
	"go.dedis.ch/kyber/v4/share"
)

// Suite describes the functionalities needed by this package in order to
// function correctly.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Encoding
	kyber.XOFFactory
	kyber.Random
}

// Some error definitions.
var ErrTooFewShares = errors.New("not enough shares to recover secret")
var ErrDifferentLengths = errors.New("inputs of different lengths")
var ErrEncVerification = errors.New("verification of encrypted share failed")
var ErrDecVerification = errors.New("verification of decrypted share failed")
var ErrCommitmentComputation = errors.New("integer too large to be represented in int64")
var ErrGlobalChallengeVerification = errors.New("failed to verify global challenge")
var ErrDecShareChallengeVerification = errors.New("failed to verify the share decryption challenge")

// PubVerShare is a public verifiable share.
type PubVerShare struct {
	S share.PubShare // Share
	P dleq.Proof     // Proof
}

// EncShares creates a list of encrypted publicly verifiable PVSS shares for
// the given secret and the list of public keys X using the sharing threshold
// t and the base point H. The function returns the list of shares and the
// public commitment polynomial.
func EncShares(suite Suite, H kyber.Point, X []kyber.Point, secret kyber.Scalar, t int) (shares []*PubVerShare, commit *share.PubPoly, err error) {
	n := len(X)
	encShares := make([]*PubVerShare, n)

	// Create secret sharing polynomial
	priPoly := share.NewPriPoly(suite, t, secret, suite.RandomStream())

	// Create secret set of shares
	priShares := priPoly.Shares(n)

	// Create public polynomial commitments with respect to basis H
	pubPoly := priPoly.Commit(H)

	// Prepare data for encryption consistency proofs ...
	indices := make([]uint32, n)
	values := make([]kyber.Scalar, n)
	HS := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		indices[i] = priShares[i].I
		values[i] = priShares[i].V
		HS[i] = H
	}

	// Create NIZK discrete-logarithm equality proofs
	proofs, _, sX, err := dleq.NewDLEQProofBatch(suite, HS, X, values)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < n; i++ {
		ps := &share.PubShare{I: indices[i], V: sX[i]}
		encShares[i] = &PubVerShare{*ps, *proofs[i]}
	}

	return encShares, pubPoly, nil
}

func computeCommitments(suite Suite, n int, polyComs []kyber.Point) ([]kyber.Point, error) {
	coms := make([]kyber.Point, n) // holds Xi in the paper
	i := big.NewInt(0)
	j := big.NewInt(0)
	exp := big.NewInt(0)
	expScalar := suite.Scalar().Zero()

	for ith := range coms {
		i.SetInt64(int64(ith + 1)) // 1 <= i <= n

		acc := suite.Point().Null()
		for jth, cj := range polyComs {
			j.SetInt64(int64(jth))
			exp.Exp(i, j, nil) // i ** j
			if !exp.IsInt64() {
				return nil, ErrCommitmentComputation
			}

			expScalar.SetInt64(exp.Int64())
			com := suite.Point().Mul(expScalar, cj) // C_j ** (i**j)
			acc.Add(acc, com)
		}

		coms[ith] = acc
	}

	return coms, nil
}

func computeGlobalChallenge(suite Suite, n int, commit *share.PubPoly, encShares []*PubVerShare) (kyber.Scalar, error) {
	_, polyComs := commit.Info()
	coms, err := computeCommitments(suite, n, polyComs)
	if err != nil {
		return nil, err
	}

	h := suite.Hash()
	for _, com := range coms {
		_, err = com.MarshalTo(h)
		if err != nil {
			return nil, err
		}
	}

	for _, share := range encShares {
		_, err = share.S.V.MarshalTo(h)
		if err != nil {
			return nil, err
		}
	}

	for _, share := range encShares {
		_, err = share.P.VG.MarshalTo(h)
		if err != nil {
			return nil, err
		}
	}

	for _, share := range encShares {
		_, err = share.P.VH.MarshalTo(h)
		if err != nil {
			return nil, err
		}
	}

	cb := h.Sum(nil)
	return suite.Scalar().Pick(suite.XOF(cb)), nil
}

// VerifyEncShare checks that the encrypted share sX satisfies
// log_{H}(sH) == log_{X}(sX) where sH is the public commitment computed by
// evaluating the public commitment polynomial at the encrypted share's index i.
func VerifyEncShare(suite Suite, H kyber.Point, X kyber.Point, sH kyber.Point, expGlobalChallenge kyber.Scalar, encShare *PubVerShare) error {
	if !encShare.P.C.Equal(expGlobalChallenge) {
		return ErrGlobalChallengeVerification
	}

	if err := encShare.P.Verify(suite, H, X, sH, encShare.S.V); err != nil {
		return ErrEncVerification
	}
	return nil
}

// VerifyEncShareBatch provides the same functionality as VerifyEncShare but for
// slices of encrypted shares. The function returns the valid encrypted shares
// together with the corresponding public keys.
func VerifyEncShareBatch(suite Suite, H kyber.Point, X []kyber.Point, sH []kyber.Point, commit *share.PubPoly, encShares []*PubVerShare) ([]kyber.Point, []*PubVerShare, error) {
	if len(X) != len(sH) || len(sH) != len(encShares) {
		return nil, nil, ErrDifferentLengths
	}
	var K []kyber.Point  // good public keys
	var E []*PubVerShare // good encrypted shares

	// Need to compute the global challenge and verify the encrypted shares
	expGlobalChallenge, err := computeGlobalChallenge(suite, len(X), commit, encShares)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < len(X); i++ {

		if err := VerifyEncShare(suite, H, X[i], sH[i], expGlobalChallenge, encShares[i]); err == nil {
			K = append(K, X[i])
			E = append(E, encShares[i])
		}
	}
	return K, E, nil
}

// DecShare first verifies the encrypted share against the encryption
// consistency proof and, if valid, decrypts it and creates a decryption
// consistency proof.
func DecShare(suite Suite, H kyber.Point, X kyber.Point, sH kyber.Point, x, expGlobalChallenge kyber.Scalar, encShare *PubVerShare) (*PubVerShare, error) {
	if err := VerifyEncShare(suite, H, X, sH, expGlobalChallenge, encShare); err != nil {
		return nil, err
	}

	G := suite.Point().Base()
	V := suite.Point().Mul(suite.Scalar().Inv(x), encShare.S.V) // decryption: x^{-1} * (xS)
	ps := &share.PubShare{I: encShare.S.I, V: V}
	P, _, _, err := dleq.NewDLEQProof(suite, G, V, x)
	if err != nil {
		return nil, err
	}
	return &PubVerShare{*ps, *P}, nil
}

// DecShareBatch provides the same functionality as DecShare but for slices of
// encrypted shares. The function returns the valid encrypted and decrypted
// shares as well as the corresponding public keys.
func DecShareBatch(suite Suite, H kyber.Point, X []kyber.Point, sH []kyber.Point, x kyber.Scalar, expGlobalChallenges []kyber.Scalar, encShares []*PubVerShare) ([]kyber.Point, []*PubVerShare, []*PubVerShare, error) {
	if len(X) != len(sH) || len(sH) != len(encShares) {
		return nil, nil, nil, ErrDifferentLengths
	}
	var K []kyber.Point  // good public keys
	var E []*PubVerShare // good encrypted shares
	var D []*PubVerShare // good decrypted shares
	for i := 0; i < len(encShares); i++ {
		if ds, err := DecShare(suite, H, X[i], sH[i], x, expGlobalChallenges[i], encShares[i]); err == nil {
			K = append(K, X[i])
			E = append(E, encShares[i])
			D = append(D, ds)
		}
	}
	return K, E, D, nil
}

// VerifyDecShare checks that the decrypted share sG satisfies
// log_{G}(X) == log_{sG}(sX). Note that X = xG and sX = s(xG) = x(sG).
func VerifyDecShare(suite Suite, G kyber.Point, X kyber.Point, encShare *PubVerShare, decShare *PubVerShare) error {
	// Compute challenge for the decShare
	h := suite.Hash()
	X.MarshalTo(h)
	encShare.S.V.MarshalTo(h)
	decShare.P.VG.MarshalTo(h)
	decShare.P.VH.MarshalTo(h)
	cb := h.Sum(nil)
	expDecChallenge := suite.Scalar().Pick(suite.XOF(cb))

	if !decShare.P.C.Equal(expDecChallenge) {
		return ErrDecShareChallengeVerification
	}

	if err := decShare.P.Verify(suite, G, decShare.S.V, X, encShare.S.V); err != nil {
		return ErrDecVerification
	}
	return nil
}

// VerifyDecShareBatch provides the same functionality as VerifyDecShare but for
// slices of decrypted shares. The function returns the the valid decrypted shares.
func VerifyDecShareBatch(suite Suite, G kyber.Point, X []kyber.Point, encShares []*PubVerShare, decShares []*PubVerShare) ([]*PubVerShare, error) {
	if len(X) != len(encShares) || len(encShares) != len(decShares) {
		return nil, ErrDifferentLengths
	}
	var D []*PubVerShare // good decrypted shares
	for i := 0; i < len(X); i++ {
		if err := VerifyDecShare(suite, G, X[i], encShares[i], decShares[i]); err == nil {
			D = append(D, decShares[i])
		}
	}
	return D, nil
}

// RecoverSecret first verifies the given decrypted shares against their
// decryption consistency proofs and then tries to recover the shared secret.
func RecoverSecret(suite Suite, G kyber.Point, X []kyber.Point, encShares []*PubVerShare, decShares []*PubVerShare, t int, n int) (kyber.Point, error) {
	D, err := VerifyDecShareBatch(suite, G, X, encShares, decShares)
	if err != nil {
		return nil, err
	}
	if len(D) < t {
		return nil, ErrTooFewShares
	}
	var shares []*share.PubShare
	for _, s := range D {
		shares = append(shares, &s.S)
	}
	return share.RecoverCommit(suite, shares, t, n)
}
