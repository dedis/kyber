package proof

import (
	"errors"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
)

// This package provides functionality to create and verify non-interactive
// zero-knowledge (NIZK) proofs for the equality (EQ) of discrete logarithms (DL).
// This means, for two values xG and xH one can check that log_{G}(xG) == log_{H}(xH)
// without revealing the secret value x.

var errorDifferentLengths = errors.New("inputs of different lengths")

// DLEQProof represents a NIZK dlog-equality proof.
type DLEQProof struct {
	C  abstract.Scalar // challenge
	R  abstract.Scalar // response
	VG abstract.Point  // public commitment with respect to base point G
	VH abstract.Point  // public commitment with respect to base point H
}

// NewDLEQProof computes a new NIZK dlog-equality proof by randomly selecting a
// commitment v, determining the challenge c = H(xG,xH,vG,vH) and the response r
// = v - cx. It also returns the encrypted base points xG and xH.
func NewDLEQProof(suite abstract.Suite, G abstract.Point, H abstract.Point, x abstract.Scalar) (proof *DLEQProof, xG abstract.Point, xH abstract.Point, err error) {

	// Encrypt base points with secret
	xG := suite.Point().Mul(G, x)
	xH := suite.Point().Mul(H, x)

	// Commitment
	v := suite.Scalar().Pick(random.Stream)
	vG := suite.Point().Mul(G, v)
	vH := suite.Point().Mul(H, v)

	// Challenge
	cb, err := hash.Args(suite.Hash(), xG, xH, vG, vH)
	if err != nil {
		return nil, nil, nil, err
	}
	c := suite.Scalar().Pick(suite.Cipher(cb))

	// Response
	r := suite.Scalar()
	r.Mul(x, c).Sub(v, r)

	return &DLEQProof{c, r, vG, vH}, xG, xH, nil
}

// NewDLEQProofBatch computes lists of NIZK dlog-equality proofs and of
// encrypted base points xG and xH. Note that the challenge is computed over all
// input values.
func NewDLEQProofBatch(suite abstract.Suite, G []abstract.Point, H []abstract.Point, secrets []abstract.Scalar) (proof []*DLEQProof, xG []abstract.Point, xH []abstract.Point, err error) {

	if len(G) != len(H) || len(H) != len(secrets) {
		return nil, nil, nil, errorDifferentLengths
	}

	n := len(secrets)
	proofs := make([]*DLEQProof, n)
	v := make([]abstract.Scalar, n)
	xG := make([]abstract.Point, n)
	xH := make([]abstract.Point, n)
	vG := make([]abstract.Point, n)
	vH := make([]abstract.Point, n)

	for i, x := range secrets {

		// Encrypt base points with secrets
		xG[i] = suite.Point().Mul(G[i], x)
		xH[i] = suite.Point().Mul(H[i], x)

		// Commitments
		v[i] = suite.Scalar().Pick(random.Stream)
		vG[i] = suite.Point().Mul(G[i], v[i])
		vH[i] = suite.Point().Mul(H[i], v[i])
	}

	// Collective challenge
	cb, err := hash.Args(suite.Hash(), xG, xH, vG, vH)
	if err != nil {
		return nil, nil, nil, err
	}
	c := suite.Scalar().Pick(suite.Cipher(cb))

	// Responses
	for i, x := range secrets {
		r := suite.Scalar()
		r.Mul(x, c).Sub(v[i], r)
		proofs[i] = &DLEQProof{c, r, vG[i], vH[i]}
	}

	return proofs, xG, xH, nil
}

// Verify examines the validity of the corresponding NIZK dlog-equality proof
// by checking that vG == rG + c(xG) and vH == rH + c(xH).
func (p *DLEQProof) Verify(suite abstract.Suite, G abstract.Point, H abstract.Point, xG abstract.Point, xH abstract.Point) bool {
	rG := suite.Point().Mul(G, p.R)
	rH := suite.Point().Mul(H, p.R)
	cxG := suite.Point().Mul(xG, p.C)
	cxH := suite.Point().Mul(xH, p.C)
	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)
	return p.VG.Equal(a) && p.VH.Equal(b)
}
