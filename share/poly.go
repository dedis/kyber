// Package share implements Shamir secret sharing and polynomial commitments.
// Shamir's scheme allows to split a secret value into multiple parts, so called
// shares, by evaluating a secret sharing polynomial at certain indices. The
// shared secret can only be reconstructed (via Lagrange interpolation) if a
// threshold of the participants provide their shares. A polynomial commitment
// scheme allows a committer to commit to a secret sharing polynomial so that
// a verifier can check the claimed evaluations of the committed polynomial.
// Both schemes of this package are core building blocks for more advanced
// secret sharing techniques.
package share

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/dedis/crypto"
)

// Some error definitions
var errorGroups = errors.New("non-matching groups")
var errorCoeffs = errors.New("different number of coefficients")

// PriShare represents a private share.
type PriShare struct {
	I int           // Index of the private share
	V kyber.Scalar // Value of the private share
}

func (p *PriShare) Hash(s kyber.Suite) []byte {
	h := s.Hash()
	p.V.MarshalTo(h)
	binary.Write(h, binary.LittleEndian, p.I)
	return h.Sum(nil)
}

// PriPoly represents a secret sharing polynomial.
type PriPoly struct {
	g      kyber.Group    // Cryptographic group
	coeffs []kyber.Scalar // Coefficients of the polynomial
}

// NewPriPoly creates a new secret sharing polynomial for the cryptographic
// group g, the secret sharing threshold t, and the secret to be shared s.
func NewPriPoly(g kyber.Group, t int, s kyber.Scalar, rand cipher.Stream) *PriPoly {
	coeffs := make([]kyber.Scalar, t)
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
func (p *PriPoly) Secret() kyber.Scalar {
	return p.coeffs[0]
}

// Eval computes the private share v = p(i).
func (p *PriPoly) Eval(i int) *PriShare {
	xi := p.g.Scalar().SetInt64(1 + int64(i))
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
	for i := range shares {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial.
func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {
	if p.g.String() != q.g.String() {
		return nil, errorGroups
	}
	if p.Threshold() != q.Threshold() {
		return nil, errorCoeffs
	}
	coeffs := make([]kyber.Scalar, p.Threshold())
	for i := range coeffs {
		coeffs[i] = p.g.Scalar().Add(p.coeffs[i], q.coeffs[i])
	}
	return &PriPoly{p.g, coeffs}, nil
}

// Equal checks equality of two secret sharing polynomials p and q.
func (p *PriPoly) Equal(q *PriPoly) bool {
	if p.g.String() != q.g.String() {
		return false
	}
	b := 1
	for i := 0; i < p.Threshold(); i++ {
		pb := p.coeffs[i].Bytes()
		qb := q.coeffs[i].Bytes()
		b &= subtle.ConstantTimeCompare(pb, qb)
	}
	return b == 1
}

// Commit creates a public commitment polynomial for the given base point b or
// the standard base if b == nil.
func (p *PriPoly) Commit(b kyber.Point) *PubPoly {
	commits := make([]kyber.Point, p.Threshold())
	for i := range commits {
		commits[i] = p.g.Point().Mul(b, p.coeffs[i])
	}
	return &PubPoly{p.g, b, commits}
}

// RecoverSecret reconstructs the shared secret p(0) from a list of private
// shares using Lagrange interpolation.
func RecoverSecret(g kyber.Group, shares []*PriShare, t, n int) (kyber.Scalar, error) {
	x := make(map[int]kyber.Scalar)
	for i, s := range shares {
		if s == nil || s.V == nil || s.I < 0 || n <= s.I {
			continue
		}
		x[i] = g.Scalar().SetInt64(1 + int64(s.I))
	}

	if len(x) < t {
		return nil, errors.New("not enough good private shares to reconstruct shared secret")
	}

	acc := g.Scalar().Zero()
	num := g.Scalar()
	den := g.Scalar()
	tmp := g.Scalar()

	for i, xi := range x {
		num.Set(shares[i].V)
		den.One()
		for j, xj := range x {
			if i == j {
				continue
			}
			num.Mul(num, xj)
			den.Mul(den, tmp.Sub(xj, xi))
		}
		acc.Add(acc, num.Div(num, den))
	}

	return acc, nil
}

// PubShare represents a public share.
type PubShare struct {
	I int          // Index of the public share
	V kyber.Point // Value of the public share
}

func (p *PubShare) Hash(s kyber.Suite) []byte {
	h := s.Hash()
	p.V.MarshalTo(h)
	binary.Write(h, binary.LittleEndian, p.I)
	return h.Sum(nil)
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	g       kyber.Group   // Cryptographic group
	b       kyber.Point   // Base point, nil for standard base
	commits []kyber.Point // Commitments to coefficients of the secret sharing polynomial
}

// NewPubPoly creates a new public commitment polynomial.
func NewPubPoly(g kyber.Group, b kyber.Point, commits []kyber.Point) *PubPoly {
	return &PubPoly{g, b, commits}
}

// Info returns the base point and the commitments to the polynomial coefficients.
func (p *PubPoly) Info() (kyber.Point, []kyber.Point) {
	return p.b, p.commits
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	return len(p.commits)
}

// Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
func (p *PubPoly) Commit() kyber.Point {
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
	for i := range shares {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial. NOTE: If the base points p.b and q.b are different then the
// base point of the resulting PubPoly cannot be computed without knowing the
// discrete logarithm between p.b and q.b. In this particular case, we are using
// p.b as a default value which of course does not correspond to the correct
// base point and thus should not be used in further computations.
func (p *PubPoly) Add(q *PubPoly) (*PubPoly, error) {
	if p.g.String() != q.g.String() {
		return nil, errorGroups
	}

	if p.Threshold() != q.Threshold() {
		return nil, errorCoeffs
	}

	commits := make([]kyber.Point, p.Threshold())
	for i := range commits {
		commits[i] = p.g.Point().Add(p.commits[i], q.commits[i])
	}

	return &PubPoly{p.g, p.b, commits}, nil
}

// Equal checks equality of two public commitment polynomials p and q.
func (p *PubPoly) Equal(q *PubPoly) bool {
	if p.g.String() != q.g.String() {
		return false
	}
	b := 1
	for i := 0; i < p.Threshold(); i++ {
		pb, _ := p.commits[i].MarshalBinary()
		qb, _ := q.commits[i].MarshalBinary()
		b &= subtle.ConstantTimeCompare(pb, qb)
	}
	return b == 1
}

// Check a private share against a public commitment polynomial.
func (p *PubPoly) Check(s *PriShare) bool {
	pv := p.Eval(s.I)
	ps := p.g.Point().Mul(p.b, s.V)
	return pv.V.Equal(ps)
}

// RecoverCommit reconstructs the secret commitment p(0) from a list of public
// shares using Lagrange interpolation.
func RecoverCommit(g kyber.Group, shares []*PubShare, t, n int) (kyber.Point, error) {
	x := make(map[int]kyber.Scalar)
	for i, s := range shares {
		if s == nil || s.V == nil || s.I < 0 || n <= s.I {
			continue
		}
		x[i] = g.Scalar().SetInt64(1 + int64(s.I))
	}

	if len(x) < t {
		return nil, errors.New("not enough good public shares to reconstruct secret commitment")
	}

	num := g.Scalar()
	den := g.Scalar()
	tmp := g.Scalar()
	Acc := g.Point().Null()
	Tmp := g.Point()

	for i, xi := range x {
		num.One()
		den.One()
		for j, xj := range x {
			if i == j {
				continue
			}
			num.Mul(num, xj)
			den.Mul(den, tmp.Sub(xj, xi))
		}
		Tmp.Mul(shares[i].V, num.Div(num, den))
		Acc.Add(Acc, Tmp)
	}

	return Acc, nil
}
