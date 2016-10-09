package poly

import (
	"errors"

	"github.com/dedis/cothority/crypto"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
)

// This package implements public verifiable secret sharing (PVSS) using
// non-interactive zero-knowledge (NIZK) proofs to show equality of discrete
// logarithms (DLE).

// DLEProof resembles a NIZK dlog-equality proof. Allows to handle multiple proofs.
type DLEProof struct {
	suite abstract.Suite
	base  []DLEProofBase
	core  []DLEProofCore
}

// DLEProofBase contains the base points against which the core proof is created.
type DLEProofBase struct {
	g abstract.Point
	h abstract.Point
}

// DLEProofCore contains the core elements of the NIZK dlog-equality proof.
type DLEProofCore struct {
	C  abstract.Scalar // challenge
	R  abstract.Scalar // response
	VG abstract.Point  // public commitment with respect to base point G
	VH abstract.Point  // public commitment with respect to base point H
}

// NewDLEProof creates a new NIZK dlog-equality proof.
func NewDLEProof(suite abstract.Suite, g []abstract.Point, h []abstract.Point, core []DLEProofCore) (*DLEProof, error) {

	if len(g) != len(h) {
		return nil, errors.New("Received non-matching number of points")
	}

	n := len(g)
	base := make([]DLEProofBase, n)
	for i := range base {
		base[i] = DLEProofBase{g: g[i], h: h[i]}
	}

	return &DLEProof{suite: suite, base: base, core: core}, nil
}

// Setup initializes the proof by randomly selecting a commitment v,
// determining the challenge c = H(xG,xH,vG,vH), and the response r = v - cx.
func (p *DLEProof) Setup(scalar ...abstract.Scalar) ([]abstract.Point, []abstract.Point, []DLEProofCore, error) {

	if len(scalar) != len(p.base) {
		return nil, nil, nil, errors.New("Received unexpected number of scalars")
	}

	n := len(scalar)
	p.core = make([]DLEProofCore, n)
	xG := make([]abstract.Point, n)
	xH := make([]abstract.Point, n)
	for i, x := range scalar {

		xG[i] = p.suite.Point().Mul(p.base[i].g, x)
		xH[i] = p.suite.Point().Mul(p.base[i].h, x)

		// Commitment
		v := p.suite.Scalar().Pick(random.Stream)
		vG := p.suite.Point().Mul(p.base[i].g, v)
		vH := p.suite.Point().Mul(p.base[i].h, v)

		// Challenge
		cb, err := crypto.HashArgsSuite(p.suite, xG[i], xH[i], vG, vH)
		if err != nil {
			return nil, nil, nil, err
		}
		c := p.suite.Scalar().Pick(p.suite.Cipher(cb))

		// Response
		r := p.suite.Scalar()
		r.Mul(x, c).Sub(v, r)

		p.core[i] = DLEProofCore{c, r, vG, vH}
	}

	return xG, xH, p.core, nil
}

// SetupCollective is similar to Setup with the difference that the challenge
// is computed as the hash over all base points and commitments.
func (p *DLEProof) SetupCollective(scalar ...abstract.Scalar) ([]abstract.Point, []abstract.Point, []DLEProofCore, error) {

	if len(scalar) != len(p.base) {
		return nil, nil, nil, errors.New("Received unexpected number of scalars")
	}

	n := len(scalar)
	p.core = make([]DLEProofCore, n)
	v := make([]abstract.Scalar, n)
	xG := make([]abstract.Point, n)
	xH := make([]abstract.Point, n)
	vG := make([]abstract.Point, n)
	vH := make([]abstract.Point, n)
	for i, x := range scalar {

		xG[i] = p.suite.Point().Mul(p.base[i].g, x)
		xH[i] = p.suite.Point().Mul(p.base[i].h, x)

		// Commitments
		v[i] = p.suite.Scalar().Pick(random.Stream)
		vG[i] = p.suite.Point().Mul(p.base[i].g, v[i])
		vH[i] = p.suite.Point().Mul(p.base[i].h, v[i])
	}

	// Collective challenge
	cb, err := crypto.HashArgsSuite(p.suite, xG, xH, vG, vH)
	if err != nil {
		return nil, nil, nil, err
	}
	c := p.suite.Scalar().Pick(p.suite.Cipher(cb))

	// Responses
	for i, x := range scalar {
		r := p.suite.Scalar()
		r.Mul(x, c).Sub(v[i], r)
		p.core[i] = DLEProofCore{c, r, vG[i], vH[i]}
	}

	return xG, xH, p.core, nil
}

// Verify validates the proof against the given input by checking that
// vG == rG + c(xG) and vH == rH + c(xH).
func (p *DLEProof) Verify(xG []abstract.Point, xH []abstract.Point) ([]int, []int, error) {

	if len(xG) != len(xH) {
		return nil, nil, errors.New("Received unexpected number of points")
	}

	var good, bad []int
	for i := range p.base {
		if xG[i].Equal(p.suite.Point().Null()) || xH[i].Equal(p.suite.Point().Null()) {
			bad = append(bad, i)
		} else {
			rG := p.suite.Point().Mul(p.base[i].g, p.core[i].R)
			rH := p.suite.Point().Mul(p.base[i].h, p.core[i].R)
			cxG := p.suite.Point().Mul(xG[i], p.core[i].C)
			cxH := p.suite.Point().Mul(xH[i], p.core[i].C)
			a := p.suite.Point().Add(rG, cxG)
			b := p.suite.Point().Add(rH, cxH)

			if p.core[i].VG.Equal(a) && p.core[i].VH.Equal(b) {
				good = append(good, i)
			} else {
				bad = append(bad, i)
			}
		}
	}

	return good, bad, nil
}

// PVSS implements public verifiable secret sharing.
type PVSS struct {
	suite abstract.Suite // Suite
	h     abstract.Point // Base point for polynomial commits
	t     int            // Secret sharing threshold
}

// NewPVSS creates a new PVSS struct using the given suite, base point, and
// secret sharing threshold.
func NewPVSS(s abstract.Suite, h abstract.Point, t int) *PVSS {
	return &PVSS{suite: s, h: h, t: t}
}

// Split creates PVSS shares encrypted by the public keys in X and
// provides a NIZK encryption consistency proof for each share.
func (pv *PVSS) Split(X []abstract.Point, secret abstract.Scalar) ([]int, []abstract.Point, []DLEProofCore, []byte, error) {

	n := len(X)

	// Create secret sharing polynomial
	priPoly := new(PriPoly).Pick(pv.suite, pv.t, secret, random.Stream)

	// Create secret set of shares
	shares := new(PriShares).Split(priPoly, n)

	// Create public polynomial commitments with respect to basis H
	pubPoly := new(PubPoly).Commit(priPoly, pv.h)

	// Prepare data for encryption consistency proofs ...
	share := make([]abstract.Scalar, n)
	H := make([]abstract.Point, n)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
		share[i] = shares.Share(i)
		H[i] = pv.h
	}

	// ... and create them
	proof, err := NewDLEProof(pv.suite, H, X, nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, sX, encProof, err := proof.SetupCollective(share...)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	polyBin, err := pubPoly.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return idx, sX, encProof, polyBin, nil
}

// Verify checks that log_H(sH) == log_X(sX) using the given proof.
func (pv *PVSS) Verify(H abstract.Point, X []abstract.Point, sH []abstract.Point, sX []abstract.Point, core []DLEProofCore) ([]int, []int, error) {

	n := len(X)
	Y := make([]abstract.Point, n)
	for i := 0; i < n; i++ {
		Y[i] = H
	}
	proof, err := NewDLEProof(pv.suite, Y, X, core)
	if err != nil {
		return nil, nil, err
	}
	return proof.Verify(sH, sX)
}

// Commits reconstructs a list of commits from the given polynomials and indices.
func (pv *PVSS) Commits(polyBin [][]byte, index []int) ([]abstract.Point, error) {

	if len(polyBin) != len(index) {
		return nil, errors.New("Inputs have different lengths")
	}

	n := len(polyBin)
	sH := make([]abstract.Point, n)
	for i := range sH {
		P := new(PubPoly)
		P.Init(pv.suite, pv.t, pv.h)
		if err := P.UnmarshalBinary(polyBin[i]); err != nil {
			return nil, err
		}
		sH[i] = P.Eval(index[i])
	}
	return sH, nil
}

// Reveal decrypts the shares in xS using the secret key x and creates an NIZK
// decryption consistency proof for each share.
func (pv *PVSS) Reveal(x abstract.Scalar, xS []abstract.Point) ([]abstract.Point, []DLEProofCore, error) {

	// Decrypt shares
	S := make([]abstract.Point, len(xS))
	G := make([]abstract.Point, len(xS))
	y := make([]abstract.Scalar, len(xS))
	for i := range xS {
		S[i] = pv.suite.Point().Mul(xS[i], pv.suite.Scalar().Inv(x))
		G[i] = pv.suite.Point().Base()
		y[i] = x
	}

	proof, err := NewDLEProof(pv.suite, G, S, nil)
	if err != nil {
		return nil, nil, err
	}
	_, _, decProof, err := proof.Setup(y...)
	if err != nil {
		return nil, nil, err
	}
	return S, decProof, nil
}

// Recover recreates the PVSS secret from the given shares.
func (pv *PVSS) Recover(pos []int, S []abstract.Point, n int) (abstract.Point, error) {

	if len(S) < pv.t {
		return nil, errors.New("Not enough shares to recover secret")
	}

	//log.Lvlf1("%v %v %v %v", pos, pv.t, len(pos), len(S))

	pp := new(PubPoly).InitNull(pv.suite, pv.t, pv.suite.Point().Base())
	ps := new(PubShares).Split(pp, n) // XXX: ackward way to init shares

	for i, s := range S {
		ps.SetShare(pos[i], s)
	}

	return ps.SecretCommit(), nil
}
