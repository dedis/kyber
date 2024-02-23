// Package dleq provides functionality to create and verify non-interactive
// zero-knowledge (NIZK) proofs for the equality (EQ) of discrete logarithms (DL).
// This means, for two values xG and xH one can check that
//
//	log_{G}(xG) == log_{H}(xH)
//
// without revealing the secret value x.
package dleq

import (
	"errors"

	"go.dedis.ch/kyber/v3"
)

// Suite wraps the functionalities needed by the dleq package.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

var errDifferentLengths = errors.New("inputs of different lengths")
var errInvalidProof = errors.New("invalid proof")

// Proof represents a NIZK dlog-equality proof.
type Proof struct {
	C  kyber.Scalar // challenge
	R  kyber.Scalar // response
	VG kyber.Point  // public commitment with respect to base point G
	VH kyber.Point  // public commitment with respect to base point H
}

// NewDLEQProof computes a new NIZK dlog-equality proof for the scalar x with
// respect to base points G and H. It therefore randomly selects a commitment v
// and then computes the challenge c = H(xG,xH,vG,vH) and response r = v - cx.
// Besides the proof, this function also returns the encrypted base points xG
// and xH.
func NewDLEQProof(
	suite Suite,
	g kyber.Point,
	h kyber.Point,
	x kyber.Scalar,
) (proof *Proof, xG kyber.Point, xH kyber.Point, err error) {
	// Encrypt base points with secret
	xG = suite.Point().Mul(x, g)
	xH = suite.Point().Mul(x, h)

	// Commitment
	v := suite.Scalar().Pick(suite.RandomStream())
	vG := suite.Point().Mul(v, g)
	vH := suite.Point().Mul(v, h)

	// Challenge
	hSuite := suite.Hash()
	_, err = xG.MarshalTo(hSuite)
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = xH.MarshalTo(hSuite)
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = vG.MarshalTo(hSuite)
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = vH.MarshalTo(hSuite)
	if err != nil {
		return nil, nil, nil, err
	}

	cb := hSuite.Sum(nil)
	c := suite.Scalar().Pick(suite.XOF(cb))

	// Response
	r := suite.Scalar()
	r.Mul(x, c).Sub(v, r)

	return &Proof{c, r, vG, vH}, xG, xH, nil
}

// NewDLEQProofBatch computes lists of NIZK dlog-equality proofs and of
// encrypted base points xG and xH. Note that the challenge is computed over all
// input values.
func NewDLEQProofBatch(
	suite Suite,
	g []kyber.Point,
	h []kyber.Point,
	secrets []kyber.Scalar,
) (proof []*Proof, xG []kyber.Point, xH []kyber.Point, err error) {
	if len(g) != len(h) || len(h) != len(secrets) {
		return nil, nil, nil, errDifferentLengths
	}

	n := len(secrets)
	proofs := make([]*Proof, n)
	v := make([]kyber.Scalar, n)
	xG = make([]kyber.Point, n)
	xH = make([]kyber.Point, n)
	vG := make([]kyber.Point, n)
	vH := make([]kyber.Point, n)

	for i, x := range secrets {
		// Encrypt base points with secrets
		xG[i] = suite.Point().Mul(x, g[i])
		xH[i] = suite.Point().Mul(x, h[i])

		// Commitments
		v[i] = suite.Scalar().Pick(suite.RandomStream())
		vG[i] = suite.Point().Mul(v[i], g[i])
		vH[i] = suite.Point().Mul(v[i], h[i])
	}

	// Collective challenge
	hSuite := suite.Hash()
	for _, x := range xG {
		_, err := x.MarshalTo(hSuite)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	for _, x := range xH {
		_, err := x.MarshalTo(hSuite)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	for _, x := range vG {
		_, err := x.MarshalTo(hSuite)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	for _, x := range vH {
		_, err := x.MarshalTo(hSuite)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	cb := hSuite.Sum(nil)

	c := suite.Scalar().Pick(suite.XOF(cb))

	// Responses
	for i, x := range secrets {
		r := suite.Scalar()
		r.Mul(x, c).Sub(v[i], r)
		proofs[i] = &Proof{c, r, vG[i], vH[i]}
	}

	return proofs, xG, xH, nil
}

// Verify examines the validity of the NIZK dlog-equality proof.
// The proof is valid if the following two conditions hold:
//
//	vG == rG + c(xG)
//	vH == rH + c(xH)
func (p *Proof) Verify(suite Suite, g kyber.Point, h kyber.Point, xG kyber.Point, xH kyber.Point) error {
	rG := suite.Point().Mul(p.R, g)
	rH := suite.Point().Mul(p.R, h)
	cxG := suite.Point().Mul(p.C, xG)
	cxH := suite.Point().Mul(p.C, xH)
	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)
	if !(p.VG.Equal(a) && p.VH.Equal(b)) {
		return errInvalidProof
	}
	return nil
}
