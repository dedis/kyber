// Package share implements different secret sharing mechanisms, including
// simple Shamir secret sharing, verifiable secret sharing (vss), and public
// verifiable secret sharing (pvss).
package share

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/crypto/abstract"
)

// This file provides the core functionality for secret sharing including
// Shamir's scheme and public commitment polynomials.

// Some error definitions
var errorGroups = errors.New("non-matching groups")
var errorCoeffs = errors.New("different number of coefficients")

// PriShare represents a private share.
type PriShare struct {
	I int             // Index of the private share
	V abstract.Scalar // Value of the private share
}

// PriPoly represents a secret sharing polynomial.
type PriPoly struct {
	g      abstract.Group    // Cryptographic group
	coeffs []abstract.Scalar // Coefficients of the polynomial
}

// NewPriPoly creates a new secret sharing polynomial for the cryptographic
// group g, the secret sharing threshold t, and the secret to be shared s.
func NewPriPoly(g abstract.Group, t int, s abstract.Scalar, rand cipher.Stream) *PriPoly {
	coeffs := make([]abstract.Scalar, t)
	coeffs[0] = s
	if coeffs[0] == nil {
		coeffs[0] = g.Scalar().Pick(rand)
	}
	for i := 1; i < t; i++ {
		coeffs[i] = g.Scalar().Pick(rand)
	}
	return &PriPoly{g, coeffs}
}

// Threshold returns the secret sharing threshold.
func (p *PriPoly) Threshold() int {
	return len(p.coeffs)
}

// GetSecret returns the shared secret p(0), i.e., the constant term of the polynomial.
func (p *PriPoly) GetSecret() abstract.Scalar {
	return p.coeffs[0]
}

// Eval computes the private share v = p(i).
func (p *PriPoly) Eval(i int) *PriShare {
	xi := p.g.Scalar().SetInt64(1 + int64(i)) // x-coordinate of this share
	v := p.g.Scalar().Zero()
	for j := p.Threshold() - 1; j >= 0; j-- {
		v.Mul(v, xi)
		v.Add(v, p.coeffs[j])
	}
	return &PriShare{i, v}
}

// Shares creates a list of n private shares p(1),...,p(n).
func (p *PriPoly) Shares(n int) []*PriShare {
	shares := make([]*PriShare, n)
	for i := 0; i < n; i++ {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial.
func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {

	if p.g != q.g {
		return nil, errorGroups
	}

	if p.Threshold() != q.Threshold() {
		return nil, errorCoeffs
	}

	t := p.Threshold()
	coeffs := make([]abstract.Scalar, t)
	for i := 0; i < t; i++ {
		coeffs[i] = p.g.Scalar().Add(p.coeffs[i], q.coeffs[i])
	}

	return &PriPoly{p.g, coeffs}, nil
}

// Equal checks equality of two secret sharing polynomials p and q.
func (p *PriPoly) Equal(q *PriPoly) bool {

	if p.g.String() != q.g.String() {
		return false
	}

	for i := 0; i < p.Threshold(); i++ {
		if !p.coeffs[i].Equal(q.coeffs[i]) {
			return false
		}
	}

	return true
}

// Commit creates a public commitment polynomial for the given base point b or
// the standard base if b == nil.
func (p *PriPoly) Commit(b abstract.Point) *PubPoly {
	t := p.Threshold()
	commits := make([]abstract.Point, t)
	for i := 0; i < t; i++ {
		commits[i] = p.g.Point().Mul(b, p.coeffs[i])
	}
	return &PubPoly{p.g, b, commits}
}

// RecoverSecret reconstructs the shared secret p(0) using Lagrange interpolation.
func RecoverSecret(g abstract.Group, shares []*PriShare, t int, n int) (abstract.Scalar, error) {

	isBad := func(s *PriShare) bool {
		return s == nil || s.V == nil || s.I < 0 || n <= s.I
	}

	c := 0
	for _, s := range shares {
		if isBad(s) {
			continue
		}
		c++
	}

	if c < t {
		return nil, errors.New("not enough good private shares to reconstruct shared secret")
	}

	acc := g.Scalar().Zero() // scalar sum accumulator
	num := g.Scalar()        // numerator
	den := g.Scalar()        // denominator
	tmp := g.Scalar()        // scalar buffer

	for _, si := range shares {
		if isBad(si) {
			continue
		}
		num.Set(si.V)
		den.One()
		xi := g.Scalar().SetInt64(1 + int64(si.I))
		for _, sj := range shares {
			if isBad(sj) || sj.I == si.I {
				continue
			}
			xj := g.Scalar().SetInt64(1 + int64(sj.I))
			num.Mul(num, xj)
			den.Mul(den, tmp.Sub(xj, xi))
		}
		acc.Add(acc, num.Div(num, den))
	}

	return acc, nil
}

// PubShare represents a public share.
type PubShare struct {
	I int            // Index of the public share
	V abstract.Point // Value of the public share
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	g       abstract.Group   // Cryptographic group
	b       abstract.Point   // Base point, nil for standard base
	commits []abstract.Point // Commitments to coefficients of the secret sharing polynomial
}

// NewPubPoly creates a new public commitment polynomial
func NewPubPoly(g abstract.Group, b abstract.Point, commits []abstract.Point) *PubPoly {
	return &PubPoly{g, b, commits}
}

// Info returns the base point and the commitments to the polynomial coefficients.
func (p *PubPoly) Info() (abstract.Point, []abstract.Point) {
	return p.b, p.commits
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	return len(p.commits)
}

// GetCommit returns the secret commitment p(0), i.e., the constant term of the polynomial.
func (p *PubPoly) GetCommit() abstract.Point {
	return p.commits[0]
}

// Eval computes the public share v = p(i).
func (p *PubPoly) Eval(i int) *PubShare {
	xi := p.g.Scalar().SetInt64(1 + int64(i)) // x-coordinate of this share
	v := p.g.Point().Null()
	for j := p.Threshold() - 1; j >= 0; j-- {
		v.Mul(v, xi)
		v.Add(v, p.commits[j])
	}
	return &PubShare{i, v}
}

// Shares creates a list of n public commitment shares p(1),...,p(n).
func (p *PubPoly) Shares(n int) []*PubShare {
	shares := make([]*PubShare, n)
	for i := 0; i < n; i++ {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial. If the base points p.b and q.b are different then the
// base point of the resulting PubPoly cannot be computed without knowing the
// discrete logarithm between p.b and q.b. In this particular case, we are using
// p.b as a default value which of cousre does not correspond to the correct
// base point.
func (p *PubPoly) Add(q *PubPoly) (*PubPoly, error) {

	if p.g != q.g {
		return nil, errorGroups
	}

	if p.Threshold() != q.Threshold() {
		return nil, errorCoeffs
	}

	t := p.Threshold()
	commits := make([]abstract.Point, t)
	for i := 0; i < t; i++ {
		commits[i] = p.g.Point().Add(p.commits[i], q.commits[i])
	}

	return &PubPoly{p.g, p.b, commits}, nil
}

// Equal checks equality of two public commitment polynomials p and q.
func (p *PubPoly) Equal(q *PubPoly) bool {

	if p.g.String() != q.g.String() {
		return false
	}

	for i := 0; i < p.Threshold(); i++ {
		if !p.commits[i].Equal(q.commits[i]) {
			return false
		}
	}

	return true
}

// Check a private share against a public commitment polynomial.
func (p *PubPoly) Check(s *PriShare) bool {
	pv := p.Eval(s.I)
	ps := p.g.Point().Mul(p.b, s.V)
	return pv.V.Equal(ps)
}

// RecoverCommit reconstructs the secret commitment p(0) using Lagrange interpolation.
func RecoverCommit(g abstract.Group, shares []*PubShare, t int, n int) (abstract.Point, error) {

	isBad := func(s *PubShare) bool {
		return s == nil || s.V == nil || s.I < 0 || n <= s.I
	}

	c := 0
	for _, s := range shares {
		if isBad(s) {
			continue
		}
		c++
	}

	if c < t {
		return nil, errors.New("not enough good public shares to reconstruct secret commitment")
	}

	num := g.Scalar()       // numerator
	den := g.Scalar()       // denominator
	tmp := g.Scalar()       // scalar buffer
	Acc := g.Point().Null() // point accumulator
	Tmp := g.Point()        // point buffer

	for _, si := range shares {
		if isBad(si) {
			continue
		}
		num.One()
		den.One()
		xi := g.Scalar().SetInt64(1 + int64(si.I))
		for _, sj := range shares {
			if isBad(sj) || sj.I == si.I {
				continue
			}
			xj := g.Scalar().SetInt64(1 + int64(sj.I))
			num.Mul(num, xj)
			den.Mul(den, tmp.Sub(xj, xi))
		}
		Tmp.Mul(si.V, num.Div(num, den))
		Acc.Add(Acc, Tmp)
	}

	return Acc, nil
}
