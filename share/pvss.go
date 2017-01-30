package share

import (
	"errors"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
)

// This package implements public verifiable secret sharing as introduced by
// Berry Schoenmakers at CRYPTO'99.

// PubVerShare is a public verifiable share.
type PubVerShare struct {
	S PubShare        // Share
	P proof.DLEQProof // Proof
}

// PVSS is the main public verifiable secret sharing struct.
type PVSS struct {
	suite abstract.Suite // Cryptographic suite
	h     abstract.Point // Base point for polynomial commits
	t     int            // Secret sharing threshold
	n     int            // Number of shares
}

// NewPVSS creates a new PVSS struct using the given suite, base point, and
// secret sharing threshold.
func NewPVSS(s abstract.Suite, h abstract.Point, t int, n int) *PVSS {
	return &PVSS{suite: s, h: h, t: t, n: n}
}

// EncShares creates encrypted PVSS shares using the public keys in X and
// provides a NIZK encryption consistency proof for each share.
func (pv *PVSS) EncShares(X []abstract.Point, secret abstract.Scalar) ([]*PubVerShare, *PubPoly, error) {

	n := len(X)
	encShares := make([]*PubVerShare, n)

	// Create secret sharing polynomial
	priPoly := NewPriPoly(pv.suite, pv.t, secret, random.Stream)

	// Create secret set of shares
	priShares := priPoly.Shares(n)

	// Create public polynomial commitments with respect to basis H
	pubPoly := priPoly.Commit(pv.h)

	// Prepare data for encryption consistency proofs ...
	indices := make([]int, n)
	values := make([]abstract.Scalar, n)
	H := make([]abstract.Point, n)
	for i := 0; i < n; i++ {
		indices[i] = priShares[i].I
		values[i] = priShares[i].V
		H[i] = pv.h
	}

	// Create NIZK discrete-logarithm equality proofs
	proofs, _, sX, err := proof.NewDLEQProofBatch(pv.suite, H, X, values)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < n; i++ {
		ps := &PubShare{indices[i], sX[i]}
		encShares[i] = &PubVerShare{*ps, *proofs[i]}
	}

	return encShares, pubPoly, nil
}

func (pv *PVSS) verifyEncShares(H abstract.Point, X []abstract.Point, polys []*PubPoly, encShares []*PubVerShare) ([]abstract.Point, []*PubVerShare, error) {

	if len(X) != len(polys) && len(polys) != len(encShares) {
		return nil, nil, errorDifferentLengths
	}

	// Recover commits from polynomials
	n := len(X)
	sH := make([]*PubShare, n)
	for i := 0; i < n; i++ {
		sH[i] = polys[i].Eval(encShares[i].S.I)
	}

	var goodKeys []abstract.Point
	var goodShares []*PubVerShare
	for i := 0; i < n; i++ {
		if encShares[i].P.Verify(pv.suite, H, X[i], sH[i].V, encShares[i].S.V) {
			goodKeys = append(goodKeys, X[i])
			goodShares = append(goodShares, encShares[i])
		}
	}

	return goodKeys, goodShares, nil
}

// DecShares first verifies the given encrypted shares against their encryption
// consistency proofs, i.e., it checks that every share sX satisfies log_H(sH)
// == log_X(sX). Afterwards all valid shares are decrypted and decryption consistency
// proofs are created.
func (pv *PVSS) DecShares(H abstract.Point, X []abstract.Point, polys []*PubPoly, x abstract.Scalar, encShares []*PubVerShare) ([]abstract.Point, []*PubVerShare, []*PubVerShare, error) {

	if len(X) != len(polys) && len(polys) != len(encShares) {
		return nil, nil, nil, errorDifferentLengths
	}

	goodKeys, goodEncShares, err := pv.verifyEncShares(H, X, polys, encShares)
	if err != nil {
		return nil, nil, nil, err
	}

	var decShares []*PubVerShare
	for _, s := range goodEncShares {

		G := pv.suite.Point().Base()
		V := pv.suite.Point().Mul(s.S.V, pv.suite.Scalar().Inv(x)) // decryption: x^{-1} * (xS)

		P, _, _, err := proof.NewDLEQProof(pv.suite, G, V, x)
		if err != nil {
			return nil, nil, nil, err
		}

		ps := &PubShare{s.S.I, V}
		decShares = append(decShares, &PubVerShare{*ps, *P})
	}

	return goodKeys, goodEncShares, decShares, nil
}

func (pv *PVSS) verifyDecShares(G abstract.Point, X []abstract.Point, encShares []*PubVerShare, decShares []*PubVerShare) ([]*PubVerShare, error) {

	if len(X) != len(encShares) || len(encShares) != len(decShares) {
		return nil, errorDifferentLengths
	}

	var goodShares []*PubVerShare
	for i := 0; i < len(X); i++ {
		if decShares[i].P.Verify(pv.suite, G, decShares[i].S.V, X[i], encShares[i].S.V) {
			goodShares = append(goodShares, decShares[i])
		}
	}

	return goodShares, nil
}

// RecoverSecret first verifies the given decrypted shares against their
// decryption consistency proofs, i.e., it checks that every share sG satisfies
// log_G(sG) == log_X(sX), and then tries to recover the shared secret.
func (pv *PVSS) RecoverSecret(G abstract.Point, X []abstract.Point, encShares []*PubVerShare, decShares []*PubVerShare) (abstract.Point, error) {

	// Verify shares before continuing
	goodShares, err := pv.verifyDecShares(G, X, encShares, decShares)
	if err != nil {
		return nil, err
	}

	// Check that we have enough good shares
	if len(goodShares) < pv.t {
		return nil, errorTooFewShares
	}

	var shares []*PubShare
	for _, s := range goodShares {
		shares = append(shares, &s.S)
	}

	return RecoverCommit(pv.suite, shares, pv.t, pv.n)
}

var errorTooFewShares = errors.New("not enough shares to recover secret")
var errorDifferentLengths = errors.New("inputs of different lengths")
