import "github.com/dedis/crypto/abstract"

// XXX: Un/Marshalling functions are still missing.

// PriShare represents an individual private share v = p(i).
type PriShare struct {
	i int             // Index of the private share
	v abstract.Scalar // Value of the private share
}

// XXX: PriShare should probably have public parameters i and v

// Info returns the index and the value of the private share
func (p *PriShare) Info() (int, abstract.Scalar) {
	return p.i, p.v
}

// PriPoly represents a secret sharing polynomial.
type PriPoly struct {
	g      abstract.Group    // Cryptographic group
	t      int               // Secret sharing threshold // XXX: corresponds to len(coeffs)
	coeffs []abstract.Scalar // Coefficients of the polynomial
}

// NewPriPoly creates a new secret sharing polynomial, with g the cryptographic
// group, t the secret sharing threshold, and s the secret to be shared.
func NewPriPoly(g abstract.Group, t int, s abstract.Scalar) *PriPoly {
	// XXX: old PriPoly.Pick()
	return nil
}

// Threshold returns the secret sharing threshold.
func (p *PriPoly) Threshold() int {
	return len(p.coeffs)
}

// SharedSecret returns the shared secret p(0), i.e., the constant term of the polynomial.
func (p *PriPoly) SharedSecret() abstract.Scalar {
	// XXX: this is the old PriPoly.Secret()
	return nil
}

// Eval computes the private share p(i).
func (p *PriPoly) Eval(i int) *PriShare {
	return nil
}

// Shares creates a list of n private shares p(1),...,p(n).
func (p *PriPoly) Shares(n int) []PriShare {
	// XXX: uses PriPoly.Eval()
	// XXX: this is the old PriShare.Split()
	return nil
}

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial.
func (p *PriPoly) Add(q *PriPoly) *PriPoly {
	return nil
}

// Equal checks equality of two secret sharing polynomials p and q.
func (p *PriPoly) Equal(q *PriPoly) bool {
	return true
}

// XXX: Do we need that?
func (p *PriPoly) String() String {
	return nil
}

// xCoords creates an array of x-coordinates for Lagrange interpolation. In the
// returned array, exactly t x-coordinates are non-nil.
func (p *PriPoly) xCoords() []abstract.Scalar {
	return nil
}

// RecoverSecret reconstructs the shared secret using Lagrange interpolation.
func (p *PriPoly) RecoverSecret(shares []PriShare, t int) abstract.Scalar {
	// XXX: this is the old PriShares.Secret()
	// XXX: maybe it should be even completely independent of the PriPoly struct
	return nil
}

// PubShare represents an individual public share v = p(i).
type PubShare struct {
	i int            // Index of the public share
	v abstract.Point // Value of the public share
}

// XXX: PubShare should probably have public parameters i and v

// Info returns the index and the value of the public share
func (p *PubShare) Info() (int, abstract.Point) {
	return p.i, p.v
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	g       abstract.Group   // Cryptographic group
	b       abstract.Point   // Base point, nil for standard base
	t       int              // Secret sharing threshold // XXX: corresponds to len(commits)
	commits []abstract.Point // Commitments to polynomial coefficients
}

// NewPubPoly creates a new public commitment polynomial.
func NewPubPoly(g abstract.Group, b abstract.Point, t int, n int) *PubPoly {
	return nil
}

// Commit to a given private polynomial.
func (p *PubPoly) Commit(q *PriPoly) {
	// XXX: compute and fill the commits inplace
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	// XXX: this is the old PubPoly.GetK()
	return len(p.commits)
}

// SecretCommit returns the secret p(0), i.e., the constant term of the polynomial.
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
func (p *PubPoly) Add(q *PubPoly) *PubPoly {
	return nil
}

// Equal checks equality of two public commitment polynomials p and q.
func (p *PubPoly) Equal(q *PubPoly) bool {
	return true
}

// Check a private share against a public commitment polynomial.
func (p *PubPoly) Check(s *PriShare) bool {
	return true
}

// XXX: Do we need that?
func (p *PubPoly) String() string {
	return nil
}

// xCoords creates an array of x-coordinates for Lagrange interpolation. In the
// returned array, exactly t x-coordinates are non-nil.
func (p *PubPoly) xCoords() []abstract.Scalar {
	return nil
}

// RecoverCommit reconstructs the secret commitment using Lagrange interpolation.
func (p *PubPoly) RecoverCommit(shares []PubShare, t int) abstract.Point {
	// XXX: this is the old PubShares.SecretCommit()
	// XXX: maybe it should be even completely independent of the PubPoly struct
	return nil
}

