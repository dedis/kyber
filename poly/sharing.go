import (
	"crypto/cipher"

	"github.com/dedis/crypto/abstract"
)

// XXX: Un/Marshalling functions are still missing.

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
func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {
	return nil, nil
}

// Equal checks equality of two secret sharing polynomials p and q.
func (p *PriPoly) Equal(q *PriPoly) (bool, error) {
	return true, nil
}

// Commit creates a public commitment polynomial for the given base point b.
func (p *PriPoly) Commit(b abstract.Point) *PubPoly {
	return nil
}

// XXX: Do we need that?
func (p *PriPoly) String() String {
	return nil
}

// coefNil is a helper function for xCoords
func (p *priPoly) coefNil(i int) bool {
	return len(p.coeffs) >= i || p.coeffs[i] == nil
}

// RecoverSecret reconstructs the shared secret p(0) using Lagrange interpolation.
func RecoverSecret(shares []PriShare, t int) (abstract.Scalar, error) {
	// XXX: this is the old PriShares.Secret()
	// XXX: uses xCoords
	return nil, nil
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
	return nil
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
	return nil
}

// coefNil is a helper function for xCoords
func (p *pubPoly) coefNil(i int) bool {
	return len(p.commits) >= i || p.commits[i] == nil
}

// RecoverCommit reconstructs the secret commitment p(0) using Lagrange interpolation.
func RecoverCommit(shares []PubShare, t int) (abstract.Point, error) {
	// XXX: this is the old PubShares.SecretCommit()
	// XXX: uses xCoords
	return nil, nil
}

// xCoords creates an array of x-coordinates for Lagrange interpolation. In the
// returned array, exactly t x-coordinates are non-nil.
func xCoords(t, n int, coefNil func(i int) bool) ([]abstract.Scalar, error) {
	// XXX: check if it's possible to merge with pubXCoords
	return nil, nil
}


