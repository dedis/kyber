import "github.com/dedis/crypto/abstract"

// XXX: Un/Marshalling functions are still missing.

// PriPoly represents a secret sharing polynomial.
type PriPoly struct {
	g      abstract.Group    // Cryptographic group
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
func (p *PriPoly) Shares(n int) *PriShares {
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

// PriShare represents an individual private share v = p(i).
type PriShare struct {
	i int             // Index of the private share
	v abstract.Scalar // Value of the private share
}

// Info returns the index and the value of the private share
func (p *PriShare) Info() (int, abstract.Scalar) {
	return p.i, p.v
}

// PriShares represents a list of private shares.
type PriShares struct {
	g      abstract.Group // Cryptographic group
	t      int            // Secret sharing threshold
	shares []PriShare     // List of private shares
}

// NewPriShares creates a new empty list of n private shares for a secret sharing threshold t.
func NewPriShares(g abstract.Group, t int, n int) *PriShares {
	// XXX: this is the old PriShares.Empty()
	return nil
}

// Set stores the given private share.
func (p *PriShares) Set(s *PriShare) {
}

// Get returns the private share at index i.
func (p *PriShares) Get(i int) *PriShare {
	return nil
}

// xCoords creates an array of x-coordinates for Lagrange interpolation. In the
// returned array, exactly t x-coordinates are non-nil.
func (p *PriShares) xCoords() []abstract.Scalar {
	return nil
}

// RecoverSecret reconstructs the shared secret using Lagrange interpolation.
func (p *PriShares) RecoverSecret() abstract.Scalar {
	// XXX: this is the old PriShares.Secret()
	return nil
}

// XXX: Do we need that?
func (p *PriShares) String() String {
	return nil
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	g       abstract.Group   // Cryptographic group
	b       abstract.Point   // Base point, nil for standard base
	commits []abstract.Point // Commitments to polynomial coefficients
}

// NewPubPoly creates a new public commitment polynomial.
func NewPubPoly(g abstract.Group, b abstract.Point, n int) *PubPoly {
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
func (p *PubPoly) Shares(n int) *PubShares {
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

// PubShare represents an individual public share v = p(i).
type PubShare struct {
	i int            // Index of the public share
	v abstract.Point // Value of the public share
}

// Info returns the index and the value of the public share
func (p *PubShare) Info() (int, abstract.Point) {
	return p.i, p.v
}

// PubShares represents a list of public shares.
type PubShares struct {
	g      abstract.Group // Cryptograhpic group
	b      abstract.Point // Base point, nil for standard base
	t      int            // Secret sharing threshold
	shares []PubShare     // List of public shares
}

// NewPubShares creates a new empty list of n public shares for a base point
// b and a secret sharing threshold t.
func NewPubShares(g abstract.Group, b abstract.Point, t int, n int) *PubShares {
	return nil
}

// Set stores the given public share.
func (p *PubShares) Set(s *PubShare) {
}

// Get returns the public share at index i.
func (p *PubShares) Get(i int) *PubShare {
	return nil
}

// xCoords creates an array of x-coordinates for Lagrange interpolation. In the
// returned array, exactly t x-coordinates are non-nil.
func (p *PubShares) xCoords() []abstract.Scalar {
	return nil
}

// RecoverCommit reconstructs the secret commitment using Lagrange interpolation.
func (p *PubShares) RecoverCommit() abstract.Point {
	// XXX: this is the old PubShares.SecretCommit()
	return nil
}

// XXX: Do we need that?
func (p *PubShares) String() string {
	return nil
}

