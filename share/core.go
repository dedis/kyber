package share

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/crypto/abstract"
)

// PriShare represents an individual private share v = p(i).
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

// SharedSecret returns the shared secret p(0), i.e., the constant term of the polynomial.
func (p *PriPoly) SharedSecret() abstract.Scalar {
	return p.coeffs[0]
}

// Eval computes the private share p(i).
func (p *PriPoly) Eval(i int) *PriShare {
	xi := p.g.Scalar().SetInt64(1 + int64(i)) // x-coordinate of this share
	sv := p.g.Scalar().Zero()
	for j := p.Threshold() - 1; j >= 0; j-- {
		sv.Mul(sv, xi)
		sv.Add(sv, p.coeffs[j])
	}
	return &PriShare{i, sv}
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
		return nil, errors.New("Non-matching groups")
	}

	if p.Threshold() != q.Threshold() {
		return nil, errors.New("Non-matching number of coefficients")
	}

	t := p.Threshold()
	coeffs := make([]abstract.Scalar, t)
	for i := 0; i < t; i++ {
		coeffs[i] = p.g.Scalar().Add(p.coeffs[i], q.coeffs[i])
	}

	return &PriPoly{p.g, coeffs}, nil
}

// Equal checks equality of two secret sharing polynomials p and q.
func (p *PriPoly) Equal(q *PriPoly) (bool, error) {

	if p.g != q.g {
		return false, errors.New("Non-matching groups")
	}

	for i := 0; i < p.Threshold(); i++ {
		if !p.coeffs[i].Equal(q.coeffs[i]) {
			return false, nil
		}
	}

	return true, nil
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

// XXX: Do we need that?
func (p *PriPoly) String() string {
	return ""
}

// RecoverSecret reconstructs the shared secret p(0) using Lagrange interpolation.
func RecoverSecret(g abstract.Group, shares []*PriShare, t int) (abstract.Scalar, error) {

	isNotNil := func(i int) bool {
		return i < len(shares) && shares[i] != nil
	}

	x, err := xCoords(g, t, len(shares), isNotNil)
	if err != nil {
		return nil, err
	}

	acc := g.Scalar().Zero() // sum accumulator
	num := g.Scalar()        // numerator temporary
	den := g.Scalar()        // denominator temporary
	tmp := g.Scalar()        // temporary

	for i := range x {
		if x[i] == nil {
			continue
		}
		num.Set(shares[i].V)
		den.One()
		for j := range x {
			if j == i || x[j] == nil {
				continue
			}
			num.Mul(num, x[j])
			den.Mul(den, tmp.Sub(x[j], x[i]))
		}
		acc.Add(acc, num.Div(num, den))
	}

	return acc, nil
}

// PubShare represents an individual public share v = p(i).
type PubShare struct {
	I int            // Index of the public share
	V abstract.Point // Value of the public share
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	g       abstract.Group   // Cryptographic group
	b       abstract.Point   // Base point, nil for standard base
	commits []abstract.Point // Commitments to polynomial coefficients
}

// NewPubPoly creates a new public commitment polynomial
func NewPubPoly(g abstract.Group, b abstract.Point, commits []abstract.Point) *PubPoly {
	return &PubPoly{g, b, commits}
}

// Info returns the base point and the commitments to the polynomial coefficients.
func (p *PubPoly) Info() (abstract.Point, []abstract.Point) {
	return nil, nil
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	// XXX: this is the old PubPoly.GetK()
	return len(p.commits)
}

// SecretCommit returns the secret commitment p(0), i.e., the constant term of the polynomial.
func (p *PubPoly) SecretCommit() abstract.Point {
	return nil
}

// Eval computes the public share p(i).
func (p *PubPoly) Eval(i int) *PubShare {
	return nil
}

// Shares creates a list of n public commitment shares p(1),...,p(n).
func (p *PubPoly) Shares(n int) []PubShare {
	// XXX: uses PubPoly.Eval()
	// XXX: this is the old PubShares.Split()
	return nil
}

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial.
func (p *PubPoly) Add(q *PubPoly) (*PubPoly, error) {
	return nil, nil
}

// Equal checks equality of two public commitment polynomials p and q.
func (p *PubPoly) Equal(q *PubPoly) (bool, error) {
	return true, nil
}

// Check a private share against a public commitment polynomial.
func (p *PubPoly) Check(s *PriShare) bool {
	return true
}

// XXX: Do we need that?
func (p *PubPoly) String() string {
	return ""
}

// RecoverCommit reconstructs the secret commitment p(0) using Lagrange interpolation.
func RecoverCommit(shares []PubShare, t int) (abstract.Point, error) {
	// XXX: this is the old PubShares.SecretCommit()
	// XXX: uses xCoords
	return nil, nil
}

// xCoords creates an array of x-coordinates for Lagrange interpolation. In the
// returned array, exactly t x-coordinates are non-nil.
func xCoords(g abstract.Group, t int, n int, isNotNil func(int) bool) ([]abstract.Scalar, error) {
	x := make([]abstract.Scalar, t)
	c := 0
	for i := 0; i < n; i++ {
		if isNotNil(i) {
			x[i] = g.Scalar().SetInt64(1 + int64(i))
			c++
			if c >= t {
				break // have enough shares, ignore any more
			}
		}
	}
	if c < t {
		return nil, errors.New("Not enough shares to reconstruct secret")
	}
	return x, nil
}
