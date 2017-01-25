package proof

import (
	"errors"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
)

// This package provides functionality to create and verify non-interactive
// zero-knowledge (NIZK) proofs for the equality (EQ) of discrete logarithms (DL).

// DLEQ resembles a NIZK dlog-equality proof. Allows to handle multiple proofs.
type DLEQ struct {
	suite abstract.Suite
	Base  []DLEQBase
	Core  []DLEQCore
}

// DLEQBase contains the base points against which the core proof is created/verified.
type DLEQBase struct {
	g abstract.Point
	h abstract.Point
}

// DLEQCore contains the core elements of the NIZK dlog-equality proof.
type DLEQCore struct {
	C  abstract.Scalar // challenge
	R  abstract.Scalar // response
	VG abstract.Point  // public commitment with respect to base point G
	VH abstract.Point  // public commitment with respect to base point H
}

// NewDLEQ creates a new NIZK dlog-equality proof.
func NewDLEQ(suite abstract.Suite, g []abstract.Point, h []abstract.Point, core []DLEQCore) (*DLEQ, error) {

	if len(g) != len(h) {
		return nil, errors.New("Received non-matching number of points")
	}

	n := len(g)
	base := make([]DLEQBase, n)
	for i := range base {
		base[i] = DLEQBase{g: g[i], h: h[i]}
	}

	return &DLEQ{suite: suite, Base: base, Core: core}, nil
}

// Setup initializes the proof by randomly selecting a commitment v,
// determining the challenge c = H(xG,xH,vG,vH) and the response r = v - cx.
func (p *DLEQ) Setup(scalar ...abstract.Scalar) ([]abstract.Point, []abstract.Point, error) {

	if len(scalar) != len(p.Base) {
		return nil, nil, errors.New("Received unexpected number of scalars")
	}

	n := len(scalar)
	p.Core = make([]DLEQCore, n)
	xG := make([]abstract.Point, n)
	xH := make([]abstract.Point, n)
	for i, x := range scalar {

		xG[i] = p.suite.Point().Mul(p.Base[i].g, x)
		xH[i] = p.suite.Point().Mul(p.Base[i].h, x)

		// Commitment
		v := p.suite.Scalar().Pick(random.Stream)
		vG := p.suite.Point().Mul(p.Base[i].g, v)
		vH := p.suite.Point().Mul(p.Base[i].h, v)

		// Challenge
		cb, err := hash.Args(p.suite.Hash(), xG[i], xH[i], vG, vH)
		if err != nil {
			return nil, nil, err
		}
		c := p.suite.Scalar().Pick(p.suite.Cipher(cb))

		// Response
		r := p.suite.Scalar()
		r.Mul(x, c).Sub(v, r)

		p.Core[i] = DLEQCore{c, r, vG, vH}
	}

	return xG, xH, nil
}

// SetupCollective is similar to Setup with the difference that the challenge
// is computed as the hash over all base points and commitments.
func (p *DLEQ) SetupCollective(scalar ...abstract.Scalar) ([]abstract.Point, []abstract.Point, error) {

	if len(scalar) != len(p.Base) {
		return nil, nil, errors.New("Received unexpected number of scalars")
	}

	n := len(scalar)
	p.Core = make([]DLEQCore, n)
	v := make([]abstract.Scalar, n)
	xG := make([]abstract.Point, n)
	xH := make([]abstract.Point, n)
	vG := make([]abstract.Point, n)
	vH := make([]abstract.Point, n)
	for i, x := range scalar {

		xG[i] = p.suite.Point().Mul(p.Base[i].g, x)
		xH[i] = p.suite.Point().Mul(p.Base[i].h, x)

		// Commitments
		v[i] = p.suite.Scalar().Pick(random.Stream)
		vG[i] = p.suite.Point().Mul(p.Base[i].g, v[i])
		vH[i] = p.suite.Point().Mul(p.Base[i].h, v[i])
	}

	// Collective challenge
	cb, err := hash.Args(p.suite.Hash(), xG, xH, vG, vH)
	if err != nil {
		return nil, nil, err
	}
	c := p.suite.Scalar().Pick(p.suite.Cipher(cb))

	// Responses
	for i, x := range scalar {
		r := p.suite.Scalar()
		r.Mul(x, c).Sub(v[i], r)
		p.Core[i] = DLEQCore{c, r, vG[i], vH[i]}
	}

	return xG, xH, nil
}

// Verify validates the proof(s) against the given input by checking that vG ==
// rG + c(xG) and vH == rH + c(xH) and returns the indices of those proofs that
// are valid (good) and non-valid (bad), respectively.
func (p *DLEQ) Verify(xG []abstract.Point, xH []abstract.Point) ([]int, []int, error) {

	if len(xG) != len(xH) {
		return nil, nil, errors.New("Received unexpected number of points")
	}

	var good, bad []int
	for i := range p.Base {
		if xG[i].Equal(p.suite.Point().Null()) || xH[i].Equal(p.suite.Point().Null()) {
			bad = append(bad, i)
		} else {
			rG := p.suite.Point().Mul(p.Base[i].g, p.Core[i].R)
			rH := p.suite.Point().Mul(p.Base[i].h, p.Core[i].R)
			cxG := p.suite.Point().Mul(xG[i], p.Core[i].C)
			cxH := p.suite.Point().Mul(xH[i], p.Core[i].C)
			a := p.suite.Point().Add(rG, cxG)
			b := p.suite.Point().Add(rH, cxH)

			if p.Core[i].VG.Equal(a) && p.Core[i].VH.Equal(b) {
				good = append(good, i)
			} else {
				bad = append(bad, i)
			}
		}
	}

	return good, bad, nil
}
