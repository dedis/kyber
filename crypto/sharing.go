// Shamir secret sharing.

package crypto

import (
	"fmt"
	"crypto/cipher"
)

// Clique protocol outline:
// 1. Leader sents Init message to all members
//	Fresh DH pubkey, max #members, loc hints?
// 2. Subset of members respond with InitAck
//	Responder DH pubkey, sig_resp(init-pubkey,resp-pubkey)
//	optional authentication here??
// 3. Leader announces pubkeys of all members
//	list of signed pubkeys, sig_int(list of signed pubkeys)
// 4. All members create secret key share, Shamir share it,
//	encrypt shares for all other members, send to leader
// 5. Leader rebroadcasts all shares, and combination, to all members
//	may be a subset of members if not all initial members responded


// Private polynomial for Shamir secret sharing.
type PriPoly struct {
	g Group			// Cryptographic group in use
	s []Secret		// Coefficients of secret polynomial
}

// Secret shares generated from a private polynomial.
type PriShares struct {
	g Group			// Cryptographic group in use
	k int			// Reconstruction threshold
	s []Secret		// Secret shares, one per sharing party.
}


// Create a fresh sharing polynomial in the Secret space of a given group.
// Shares the provided Secret s, or picks a random one if s == nil.
func (p *PriPoly) Pick(g Group, k int, s0 Secret,
			rand cipher.Stream) *PriPoly {
	p.g = g
	s := make([]Secret, k)
	if s0 == nil {		// Choose secret to share if none provided
		s0 = g.Secret().Pick(rand)
	}
	s[0] = s0
	for i := 1; i < k; i++ {
		s[i] = g.Secret().Pick(rand)
	}
	p.s = s
	return p
}

// Return the shared secret from a private sharing polynomial.
func (p *PriPoly) Secret() Secret {
	return p.s[0]
}

// Test polynomials for equality component-wise.
// Assumes they are of the same degree and from the same Secret field.
func (p1 *PriPoly) Equal(p2 *PriPoly) bool {
	k := len(p1.s)
	if p1.g != p2.g || k != len(p2.s) {
		panic("Mismatched polynomials")
	}
	for i := 0; i < len(p1.s); i++ {
		if !p1.s[i].Equal(p2.s[i]) {
			return false
		}
	}
	return true
}

// Set to the component-wise addition of two polynomials,
// which are assumed to be of the same degree and from the same Secret field.
func (p *PriPoly) Add(p1,p2 *PriPoly) *PriPoly {
	g := p1.g
	k := len(p1.s)
	if g != p2.g || k != len(p2.s) {
		panic("Mismatched polynomials")
	}
	s := make([]Secret, k)
	for i := 0; i < k; i++ {
		s[i] = g.Secret().Add(p1.s[i],p2.s[i])
	}
	p.g = g
	p.s = s
	return p
}

// Dump a string representation of the polynomial.
func (p *PriPoly) String() string {
	k := len(p.s)
	s := p.s[0].String()
	for i := 1; i < k; i++ {
		s += fmt.Sprintf("+%s*x", p.s[i].String())
		if i > 1 {
			s += fmt.Sprintf("^%d", i)
		}
	}
	return s
}


// Create a desired number of secret-shares from a private polynomial,
// each of which is typically to be distributed to a distinct party.
// Any k of these shares may be used to reconstruct the original secret.
// Amounts to evaluating the private polynomial at positions 1, ..., n.
func (ps *PriShares) Split(p *PriPoly, n int) *PriShares {
	g := p.g
	k := len(p.s)
	s := make([]Secret, n)
	xi := g.Secret()		// temporary x-coordinate
	for i := 0; i < n; i++ {
		// Evaluate private polynomial at x-coordinate 1+i
		xi.SetInt64(1+int64(i))
		sv := g.Secret().Zero()
		for j := k-1; j >= 0; j-- {
			sv.Mul(sv,xi)
			sv.Add(sv,p.s[j])
		}
		s[i] = sv
	}
	ps.g = g
	ps.k = k
	ps.s = s
	return ps
}

// Return a given node i's share.
func (ps *PriShares) Share(i int) Secret {
	return ps.s[i]
}

// Initialize a set of secret-shares to an initially empty list,
// before populating using SetShare() and reconstruction.
func (ps *PriShares) Empty(g Group, k,n int) {
	ps.g = g
	ps.k = k
	ps.s = make([]Secret, n)
}

// Set node i's share.
func (ps *PriShares) SetShare(i int, s Secret) {
	ps.s[i] = s
}

// Create an array of x-coordinates we need for Lagrange interpolation.
// In the returned array, exactly k x-coordinates are non-nil.
func (ps *PriShares) xCoords() []Secret {
	x := make([]Secret, len(ps.s))
	c := 0
	for i := range(ps.s) {
		if ps.s[i] != nil {
			x[i] = ps.g.Secret().SetInt64(1+int64(i))
			c++
			if c >= ps.k {
				break	// have enough shares, ignore any more
			}
		}
	}
	if c < ps.k {
		panic("Not enough shares to reconstruct secret")
	}
	return x
}

// Use Lagrange interpolation to reconstruct a secret,
// from a private share array of which
// at least a threshold k of shares are populated (non-nil).
func (ps *PriShares) Secret() Secret {

	// compute Lagrange interpolation for point x=0 (the shared secret)
	x := ps.xCoords()
	a := ps.g.Secret().Zero()	// sum accumulator
	n := ps.g.Secret()		// numerator temporary
	d := ps.g.Secret()		// denominator temporary
	t := ps.g.Secret()		// temporary
	for i := range(x) {
		if x[i] == nil {
			continue
		}
		n.Set(ps.s[i])
		d.One()
		for j := range(x) {
			if j == i || x[j] == nil {
				continue
			}
			n.Mul(n,x[j])
			d.Mul(d,t.Sub(x[j],x[i]))
		}
		a.Add(a,n.Div(n,d))
	}
	return a
}

func (ps *PriShares) String() string {
	s := "{"
	for i := range(ps.s) {
		if i > 0 {
			s += ","
		}
		if ps.s[i] != nil {
			s += ps.s[i].String()
		} else {
			s += "<missing>"
		}
	}
	s += "}"
	return s
}


// A public commitment to a secret-sharing polynomial.
type PubPoly struct {
	g Group			// Cryptographic group in use
	p []Point		// Commitments to polynomial coefficients
}

// Initialize to a public commitment to a given private polynomial.
func (pub *PubPoly) Commit(pri *PriPoly) *PubPoly {
	g := pri.g
	k := len(pri.s)
	p := make([]Point, k)
	for i := 0; i < k; i++ {
		p[i] = g.Point().BaseMul(pri.s[i])
	}
	pub.g = g
	pub.p = p
	return pub
}

// Test polynomial commitments for equality.
// Assumes they are of the same degree and from the same group.
func (p1 *PubPoly) Equal(p2 *PubPoly) bool {
	k := len(p1.p)
	if p1.g != p2.g || k != len(p2.p) {
		panic("Mismatched polynomial commitments")
	}
	for i := 0; i < len(p1.p); i++ {
		if !p1.p[i].Equal(p2.p[i]) {
			return false
		}
	}
	return true
}

// Homomorphically add two public polynomial commitments,
// to form a public commitment to the sum of the two polynomials.
func (pub *PubPoly) Add(p1,p2 *PubPoly) *PubPoly {
	g := p1.g
	k := len(p1.p)
	if p1.g != p2.g || k != len(p2.p) {
		panic("Mismatched polynomial commitments")
	}
	p := make([]Point, k)
	for i := 0; i < k; i++ {
		p[i] = g.Point().Add(p1.p[i],p2.p[i])
	}
	pub.g = g
	pub.p = p
	return pub
}

// Check a secret share against a public polynomial commitment.
// This amounts to evaluating the polynomial under homomorphic encryption.
func (pub *PubPoly) Check(i int, share Secret) bool {
	g := pub.g
	k := len(pub.p)
	xi := g.Secret().SetInt64(1+int64(i))	// x-coordinate of this share
	pv := g.Point().Null()
	for i = k-1; i >= 0; i-- {
		pv.Mul(pv,xi)
		pv.Add(pv,pub.p[i])
	}

	ps := g.Point().BaseMul(share)
	return pv.Equal(ps)
}

// Dump a string representation of the polynomial commitment.
func (p *PubPoly) String() string {
	k := len(p.p)
	s := p.p[0].String()
	for i := 1; i < k; i++ {
		s += fmt.Sprintf(",%s", p.p[i].String())
	}
	return s
}


func testSharing(g Group) {

	k := 4
	n := 10
	p1 := new(PriPoly).Pick(g,k,nil,RandomStream)
	p2 := new(PriPoly).Pick(g,k,nil,RandomStream)
	p3 := new(PriPoly).Add(p1,p2)
	if p1.Equal(p2) || p1.Equal(p3) || !p1.Equal(p1) || !p2.Equal(p2) {
		panic("PriPoly equality doesn't work")
	}

	pub1 := new(PubPoly).Commit(p1)
	pub2 := new(PubPoly).Commit(p2)
	pub3 := new(PubPoly).Commit(p3)
	if pub1.Equal(pub2) || pub1.Equal(pub3) {
		panic("PubPoly equality false positive")
	}
	if !pub1.Equal(pub1) || !pub2.Equal(pub2) {
		panic("PubPoly equality false negative")
	}
	pub3c := new(PubPoly).Add(pub1,pub2)
	if !pub3.Equal(pub3c) {
		panic("PubPoly homomorphic addition doesn't work")
	}

	ps1 := new(PriShares).Split(p1,n)
	if !ps1.Secret().Equal(p1.Secret()) {
		panic("Secret recovery doesn't work!")
	}

	// Share-checking
	for i := 0; i < n; i++ {
		if !pub1.Check(i, ps1.Share(i)) {
			panic("Share checking doesn't work")
		}
		if pub2.Check(i, ps1.Share(i)) {
			panic("Share checking false positive!?")
		}
	}

	// Cut out even-numbered shares for fun
	for i := 0; i < n; i += 2 {
		ps1.SetShare(i, nil)
	}
	if !ps1.Secret().Equal(p1.Secret()) {
		panic("Secret recovery from partial set doesn't work!")
	}

	// Cut to the minimum
	ps1.SetShare(1, nil)
	if !ps1.Secret().Equal(p1.Secret()) {
		panic("Secret recovery from partial set doesn't work!")
	}
}

