package proof

import (
	"errors"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
)

// This package provides functionality to create and verify non-interactive
// zero-knowledge (NIZK) proofs for the equality (EQ) of discrete logarithms (DL).

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
func NewDLEQProof(suite abstract.Suite, g abstract.Point, h abstract.Point, x abstract.Scalar) (*DLEQProof, abstract.Point, abstract.Point, error) {

	// Encrypt base points with secret
	xG := suite.Point().Mul(g, x)
	xH := suite.Point().Mul(h, x)

	// Commitment
	v := suite.Scalar().Pick(random.Stream)
	vG := suite.Point().Mul(g, v)
	vH := suite.Point().Mul(h, v)

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
func NewDLEQProofBatch(suite abstract.Suite, g []abstract.Point, h []abstract.Point, secrets []abstract.Scalar) ([]*DLEQProof, []abstract.Point, []abstract.Point, error) {

	if (len(g) != len(h)) && (len(h) != len(secrets)) {
		return nil, nil, nil, errors.New("inputs of different lengths")
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
		xG[i] = suite.Point().Mul(g[i], x)
		xH[i] = suite.Point().Mul(h[i], x)

		// Commitments
		v[i] = suite.Scalar().Pick(random.Stream)
		vG[i] = suite.Point().Mul(g[i], v[i])
		vH[i] = suite.Point().Mul(h[i], v[i])
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
func (p *DLEQProof) Verify(suite abstract.Suite, g abstract.Point, h abstract.Point, xG abstract.Point, xH abstract.Point) bool {
	rG := suite.Point().Mul(g, p.R)
	rH := suite.Point().Mul(h, p.R)
	cxG := suite.Point().Mul(xG, p.C)
	cxH := suite.Point().Mul(xH, p.C)
	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)
	if p.VG.Equal(a) && p.VH.Equal(b) {
		return true
	}
	return false
}
