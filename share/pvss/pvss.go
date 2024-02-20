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

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"
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
var errorTooFewShares = errors.New("not enough shares to recover secret")
var errorDifferentLengths = errors.New("inputs of different lengths")
var errorEncVerification = errors.New("verification of encrypted share failed")
var errorDecVerification = errors.New("verification of decrypted share failed")

// PubVerShare is a public verifiable share.
type PubVerShare struct {
	S share.PubShare // Share
	P dleq.Proof     // Proof
}

// EncShares creates a list of encrypted publicly verifiable PVSS shares for
// the given secret and the list of public keys X using the sharing threshold
// t and the base point h. The function returns the list of shares and the
// public commitment polynomial.
func EncShares(suite Suite, h kyber.Point, x []kyber.Point, secret kyber.Scalar, t int) (shares []*PubVerShare, commit *share.PubPoly, err error) {
	n := len(x)
	encShares := make([]*PubVerShare, n)

	// Create secret sharing polynomial
	priPoly := share.NewPriPoly(suite, t, secret, suite.RandomStream())

	// Create secret set of shares
	priShares := priPoly.Shares(n)

	// Create public polynomial commitments with respect to basis h
	pubPoly := priPoly.Commit(h)

	// Prepare data for encryption consistency proofs ...
	indices := make([]int, n)
	values := make([]kyber.Scalar, n)
	HS := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		indices[i] = priShares[i].I
		values[i] = priShares[i].V
		HS[i] = h
	}

	// Create NIZK discrete-logarithm equality proofs
	proofs, _, sX, err := dleq.NewDLEQProofBatch(suite, HS, x, values)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < n; i++ {
		ps := &share.PubShare{I: indices[i], V: sX[i]}
		encShares[i] = &PubVerShare{*ps, *proofs[i]}
	}

	return encShares, pubPoly, nil
}

// VerifyEncShare checks that the encrypted share sX satisfies
// log_{h}(sH) == log_{X}(sX) where sH is the public commitment computed by
// evaluating the public commitment polynomial at the encrypted share's index i.
func VerifyEncShare(suite Suite, h kyber.Point, x kyber.Point, sH kyber.Point, encShare *PubVerShare) error {
	if err := encShare.P.Verify(suite, h, x, sH, encShare.S.V); err != nil {
		return errorEncVerification
	}
	return nil
}

// VerifyEncShareBatch provides the same functionality as VerifyEncShare but for
// slices of encrypted shares. The function returns the valid encrypted shares
// together with the corresponding public keys.
func VerifyEncShareBatch(suite Suite, h kyber.Point, x []kyber.Point, sH []kyber.Point, encShares []*PubVerShare) ([]kyber.Point, []*PubVerShare, error) {
	if len(x) != len(sH) || len(sH) != len(encShares) {
		return nil, nil, errorDifferentLengths
	}
	var K []kyber.Point  // good public keys
	var E []*PubVerShare // good encrypted shares
	for i := 0; i < len(x); i++ {
		if err := VerifyEncShare(suite, h, x[i], sH[i], encShares[i]); err == nil {
			K = append(K, x[i])
			E = append(E, encShares[i])
		}
	}
	return K, E, nil
}

// DecShare first verifies the encrypted share against the encryption
// consistency proof and, if valid, decrypts it and creates a decryption
// consistency proof.
func DecShare(suite Suite, h kyber.Point, x kyber.Point, sH kyber.Point, s kyber.Scalar, encShare *PubVerShare) (*PubVerShare, error) {
	if err := VerifyEncShare(suite, h, x, sH, encShare); err != nil {
		return nil, err
	}
	G := suite.Point().Base()
	V := suite.Point().Mul(suite.Scalar().Inv(s), encShare.S.V) // decryption: s^{-1} * (xS)
	ps := &share.PubShare{I: encShare.S.I, V: V}
	P, _, _, err := dleq.NewDLEQProof(suite, G, V, s)
	if err != nil {
		return nil, err
	}
	return &PubVerShare{*ps, *P}, nil
}

// DecShareBatch provides the same functionality as DecShare but for slices of
// encrypted shares. The function returns the valid encrypted and decrypted
// shares as well as the corresponding public keys.
func DecShareBatch(suite Suite, h kyber.Point, x []kyber.Point, sH []kyber.Point, s kyber.Scalar, encShares []*PubVerShare) ([]kyber.Point, []*PubVerShare, []*PubVerShare, error) {
	if len(x) != len(sH) || len(sH) != len(encShares) {
		return nil, nil, nil, errorDifferentLengths
	}
	var K []kyber.Point  // good public keys
	var E []*PubVerShare // good encrypted shares
	var D []*PubVerShare // good decrypted shares
	for i := 0; i < len(encShares); i++ {
		if ds, err := DecShare(suite, h, x[i], sH[i], s, encShares[i]); err == nil {
			K = append(K, x[i])
			E = append(E, encShares[i])
			D = append(D, ds)
		}
	}
	return K, E, D, nil
}

// VerifyDecShare checks that the decrypted share sG satisfies
// log_{G}(X) == log_{sG}(sX). Note that X = xG and sX = s(xG) = x(sG).
func VerifyDecShare(suite Suite, g kyber.Point, x kyber.Point, encShare *PubVerShare, decShare *PubVerShare) error {
	if err := decShare.P.Verify(suite, g, decShare.S.V, x, encShare.S.V); err != nil {
		return errorDecVerification
	}
	return nil
}

// VerifyDecShareBatch provides the same functionality as VerifyDecShare but for
// slices of decrypted shares. The function returns the valid decrypted shares.
func VerifyDecShareBatch(suite Suite, g kyber.Point, x []kyber.Point, encShares []*PubVerShare, decShares []*PubVerShare) ([]*PubVerShare, error) {
	if len(x) != len(encShares) || len(encShares) != len(decShares) {
		return nil, errorDifferentLengths
	}
	var D []*PubVerShare // good decrypted shares
	for i := 0; i < len(x); i++ {
		if err := VerifyDecShare(suite, g, x[i], encShares[i], decShares[i]); err == nil {
			D = append(D, decShares[i])
		}
	}
	return D, nil
}

// RecoverSecret first verifies the given decrypted shares against their
// decryption consistency proofs and then tries to recover the shared secret.
func RecoverSecret(suite Suite, g kyber.Point, x []kyber.Point, encShares []*PubVerShare, decShares []*PubVerShare, t int, n int) (kyber.Point, error) {
	D, err := VerifyDecShareBatch(suite, g, x, encShares, decShares)
	if err != nil {
		return nil, err
	}
	if len(D) < t {
		return nil, errorTooFewShares
	}
	var shares []*share.PubShare
	for _, s := range D {
		shares = append(shares, &s.S)
	}
	return share.RecoverCommit(suite, shares, t, n)
}
