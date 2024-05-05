package share

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestSecretRecovery(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 6
	t := 5
	poly := NewPriPoly(g, t, nil, g.RandomStream())
	fmt.Println("polynom has degree ", len(poly.coeffs)-1)
	shares := poly.Shares(n)

	recovered, err := RecoverSecret(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(poly.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}
	pp, _ := RecoverPriPoly(g, shares, t, n)
	require.True(test, poly.Equal(pp))
}

// tests the recovery of a secret when one of the share has an index
// higher than the given `n`. This is a valid scenario that can happen during
// a DKG-resharing:
//  1. we add a new node n6 to an already-established group of 5 nodes.
//  2. DKG runs without the first node in the group, i.e. without n1
//  3. The list of qualified shares are [n2 ... n6] so the new resulting group
//     has 5 members (no need to keep the 1st node around).
//  4. When n6 wants to reconstruct, it will give its index given during the
//
// resharing, i.e. 6 (or 5 in 0-based indexing) whereas n = 5.
// See TestPublicRecoveryOutIndex for testing with the commitment.
func TestSecretRecoveryOutIndex(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	poly := NewPriPoly(g, t, nil, g.RandomStream())
	shares := poly.Shares(n)

	selected := shares[n-t:]
	require.Len(test, selected, t)
	newN := t + 1

	recovered, err := RecoverSecret(g, selected, t, newN)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(poly.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}
}

func TestSecretRecoveryDelete(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	poly := NewPriPoly(g, t, nil, g.RandomStream())
	shares := poly.Shares(n)

	// Corrupt a few shares
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	recovered, err := RecoverSecret(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(poly.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}
}

func TestSecretRecoveryDeleteFail(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	poly := NewPriPoly(g, t, nil, g.RandomStream())
	shares := poly.Shares(n)

	// Corrupt one more share than acceptable
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	_, err := RecoverSecret(g, shares, t, n)
	if err == nil {
		test.Fatal("recovered secret unexpectably")
	}
}

func TestSecretPolyEqual(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	p1 := NewPriPoly(g, t, nil, g.RandomStream())
	p2 := NewPriPoly(g, t, nil, g.RandomStream())
	p3 := NewPriPoly(g, t, nil, g.RandomStream())

	p12, _ := p1.Add(p2)
	p13, _ := p1.Add(p3)

	p123, _ := p12.Add(p3)
	p132, _ := p13.Add(p2)

	if !p123.Equal(p132) {
		test.Fatal("private polynomials not equal")
	}
}

func TestPublicCheck(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, nil, g.RandomStream())
	priShares := priPoly.Shares(n)
	pubPoly := priPoly.Commit(nil)

	for i, share := range priShares {
		if !pubPoly.Check(share) {
			test.Fatalf("private share %v not valid with respect to the public commitment polynomial", i)
		}
	}
}

func TestBenchy(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 100
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, nil, g.RandomStream())
	pubPoly := priPoly.Commit(nil)
	pubShares := pubPoly.Shares(n)

	now1 := time.Now()
	_, err := RecoverCommit(g, pubShares, t, n)
	//now2 := time.Now()
	fmt.Println("time elapsed: ", time.Since(now1))
	if err != nil {
		test.Fatal(err)
	}

	now1 = time.Now()
	RecoverPubPoly(g, pubShares, t, n)

	fmt.Println("time elapsed public poly: ", time.Since(now1))
}

func TestPublicRecovery(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, nil, g.RandomStream())
	pubPoly := priPoly.Commit(nil)
	pubShares := pubPoly.Shares(n)

	recovered, err := RecoverCommit(g, pubShares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(pubPoly.Commit()) {
		test.Fatal("recovered commit does not match initial value")
	}

	polyRecovered, err := RecoverPubPoly(g, pubShares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	require.True(test, pubPoly.Equal(polyRecovered))
}

func TestPublicRecoveryOutIndex(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, nil, g.RandomStream())
	pubPoly := priPoly.Commit(nil)
	pubShares := pubPoly.Shares(n)

	selected := pubShares[n-t:]
	require.Len(test, selected, t)
	newN := t + 1

	recovered, err := RecoverCommit(g, selected, t, newN)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(pubPoly.Commit()) {
		test.Fatal("recovered commit does not match initial value")
	}

	polyRecovered, err := RecoverPubPoly(g, pubShares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	require.True(test, pubPoly.Equal(polyRecovered))
}

func TestPublicRecoveryDelete(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, nil, g.RandomStream())
	pubPoly := priPoly.Commit(nil)
	shares := pubPoly.Shares(n)

	// Corrupt a few shares
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	recovered, err := RecoverCommit(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(pubPoly.Commit()) {
		test.Fatal("recovered commit does not match initial value")
	}
}

func TestPublicRecoveryDeleteFail(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, nil, g.RandomStream())
	pubPoly := priPoly.Commit(nil)
	shares := pubPoly.Shares(n)

	// Corrupt one more share than acceptable
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	_, err := RecoverCommit(g, shares, t, n)
	if err == nil {
		test.Fatal("recovered commit unexpectably")
	}
}

func TestPrivateAdd(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	p := NewPriPoly(g, t, nil, g.RandomStream())
	q := NewPriPoly(g, t, nil, g.RandomStream())

	r, err := p.Add(q)
	if err != nil {
		test.Fatal(err)
	}

	ps := p.Secret()
	qs := q.Secret()
	rs := g.Scalar().Add(ps, qs)

	if !rs.Equal(r.Secret()) {
		test.Fatal("addition of secret sharing polynomials failed")
	}
}

func TestPublicAdd(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	G := g.Point().Pick(g.RandomStream())
	H := g.Point().Pick(g.RandomStream())

	p := NewPriPoly(g, t, nil, g.RandomStream())
	q := NewPriPoly(g, t, nil, g.RandomStream())

	P := p.Commit(G)
	Q := q.Commit(H)

	R, err := P.Add(Q)
	if err != nil {
		test.Fatal(err)
	}

	shares := R.Shares(n)
	recovered, err := RecoverCommit(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	x := P.Commit()
	y := Q.Commit()
	z := g.Point().Add(x, y)

	if !recovered.Equal(z) {
		test.Fatal("addition of public commitment polynomials failed")
	}
}

func TestPublicPolyEqual(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	G := g.Point().Pick(g.RandomStream())

	p1 := NewPriPoly(g, t, nil, g.RandomStream())
	p2 := NewPriPoly(g, t, nil, g.RandomStream())
	p3 := NewPriPoly(g, t, nil, g.RandomStream())

	P1 := p1.Commit(G)
	P2 := p2.Commit(G)
	P3 := p3.Commit(G)

	P12, _ := P1.Add(P2)
	P13, _ := P1.Add(P3)

	P123, _ := P12.Add(P3)
	P132, _ := P13.Add(P2)

	if !P123.Equal(P132) {
		test.Fatal("public polynomials not equal")
	}
}

func TestPriPolyMul(test *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	a := NewPriPoly(suite, t, nil, suite.RandomStream())
	b := NewPriPoly(suite, t, nil, suite.RandomStream())

	c := a.Mul(b)
	assert.Equal(test, len(a.coeffs)+len(b.coeffs)-1, len(c.coeffs))
	nul := suite.Scalar().Zero()
	for _, coeff := range c.coeffs {
		assert.NotEqual(test, nul.String(), coeff.String())
	}

	a0 := a.coeffs[0]
	b0 := b.coeffs[0]
	mul := suite.Scalar().Mul(b0, a0)
	c0 := c.coeffs[0]
	assert.Equal(test, c0.String(), mul.String())

	at := a.coeffs[len(a.coeffs)-1]
	bt := b.coeffs[len(b.coeffs)-1]
	mul = suite.Scalar().Mul(at, bt)
	ct := c.coeffs[len(c.coeffs)-1]
	assert.Equal(test, ct.String(), mul.String())
}

func TestRecoverPriPoly(test *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	a := NewPriPoly(suite, t, nil, suite.RandomStream())

	shares := a.Shares(n)
	reverses := make([]*PriShare, len(shares))
	l := len(shares) - 1
	for i := range shares {
		reverses[l-i] = shares[i]
	}
	recovered, err := RecoverPriPoly(suite, shares, t, n)
	assert.Nil(test, err)

	reverseRecovered, err := RecoverPriPoly(suite, reverses, t, n)
	assert.Nil(test, err)

	for i := 0; i < t; i++ {
		assert.Equal(test, recovered.Eval(i).V.String(), a.Eval(i).V.String())
		assert.Equal(test, reverseRecovered.Eval(i).V.String(), a.Eval(i).V.String())
	}
}

func TestPriPolyCoefficients(test *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	a := NewPriPoly(suite, t, nil, suite.RandomStream())

	coeffs := a.Coefficients()
	require.Len(test, coeffs, t)

	b := CoefficientsToPriPoly(suite, coeffs)
	require.Equal(test, a.coeffs, b.coeffs)

}

func TestRefreshDKG(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	// Run an n-fold Pedersen VSS (= DKG)
	priPolys := make([]*PriPoly, n)
	priShares := make([][]*PriShare, n)
	pubPolys := make([]*PubPoly, n)
	pubShares := make([][]*PubShare, n)
	for i := 0; i < n; i++ {
		priPolys[i] = NewPriPoly(g, t, nil, g.RandomStream())
		priShares[i] = priPolys[i].Shares(n)
		pubPolys[i] = priPolys[i].Commit(nil)
		pubShares[i] = pubPolys[i].Shares(n)
	}

	// Verify VSS shares
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			sij := priShares[i][j]
			// s_ij * G
			sijG := g.Point().Base().Mul(sij.V, nil)
			require.True(test, sijG.Equal(pubShares[i][j].V))
		}
	}

	// Create private DKG shares
	dkgShares := make([]*PriShare, n)
	for i := 0; i < n; i++ {
		acc := g.Scalar().Zero()
		for j := 0; j < n; j++ { // assuming all participants are in the qualified set
			acc = g.Scalar().Add(acc, priShares[j][i].V)
		}
		dkgShares[i] = &PriShare{i, acc}
	}

	// Create public DKG commitments (= verification vector)
	dkgCommits := make([]kyber.Point, t)
	for k := 0; k < t; k++ {
		acc := g.Point().Null()
		for i := 0; i < n; i++ { // assuming all participants are in the qualified set
			_, coeff := pubPolys[i].Info()
			acc = g.Point().Add(acc, coeff[k])
		}
		dkgCommits[k] = acc
	}

	// Check that the private DKG shares verify against the public DKG commits
	dkgPubPoly := NewPubPoly(g, nil, dkgCommits)
	for i := 0; i < n; i++ {
		require.True(test, dkgPubPoly.Check(dkgShares[i]))
	}

	// Start verifiable resharing process
	subPriPolys := make([]*PriPoly, n)
	subPriShares := make([][]*PriShare, n)
	subPubPolys := make([]*PubPoly, n)
	subPubShares := make([][]*PubShare, n)

	// Create subshares and subpolys
	for i := 0; i < n; i++ {
		subPriPolys[i] = NewPriPoly(g, t, dkgShares[i].V, g.RandomStream())
		subPriShares[i] = subPriPolys[i].Shares(n)
		subPubPolys[i] = subPriPolys[i].Commit(nil)
		subPubShares[i] = subPubPolys[i].Shares(n)
		require.True(test, g.Point().Mul(subPriShares[i][0].V, nil).Equal(subPubShares[i][0].V))
	}

	// Handout shares to new nodes column-wise and verify them
	newDKGShares := make([]*PriShare, n)
	for i := 0; i < n; i++ {
		tmpPriShares := make([]*PriShare, n) // column-wise reshuffled sub-shares
		tmpPubShares := make([]*PubShare, n) // public commitments to old DKG private shares
		for j := 0; j < n; j++ {
			// Check 1: Verify that the received individual private subshares s_ji
			// is correct by evaluating the public commitment vector
			tmpPriShares[j] = &PriShare{I: j, V: subPriShares[j][i].V} // Shares that participant i gets from j
			require.True(test, g.Point().Mul(tmpPriShares[j].V, nil).Equal(subPubPolys[j].Eval(i).V))

			// Check 2: Verify that the received sub public shares are
			// commitments to the original secret
			tmpPubShares[j] = dkgPubPoly.Eval(j)
			require.True(test, tmpPubShares[j].V.Equal(subPubPolys[j].Commit()))
		}
		// Check 3: Verify that the received public shares interpolate to the
		// original DKG public key
		com, err := RecoverCommit(g, tmpPubShares, t, n)
		require.NoError(test, err)
		require.True(test, dkgCommits[0].Equal(com))

		// Compute the refreshed private DKG share of node i
		s, err := RecoverSecret(g, tmpPriShares, t, n)
		require.NoError(test, err)
		newDKGShares[i] = &PriShare{I: i, V: s}
	}

	// Refresh the DKG commitments (= verification vector)
	newDKGCommits := make([]kyber.Point, t)
	for i := 0; i < t; i++ {
		pubShares := make([]*PubShare, n)
		for j := 0; j < n; j++ {
			_, c := subPubPolys[j].Info()
			pubShares[j] = &PubShare{I: j, V: c[i]}
		}
		com, err := RecoverCommit(g, pubShares, t, n)
		require.NoError(test, err)
		newDKGCommits[i] = com
	}

	// Check that the old and new DKG public keys are the same
	require.True(test, dkgCommits[0].Equal(newDKGCommits[0]))

	// Check that the old and new DKG private shares are different
	for i := 0; i < n; i++ {
		require.False(test, dkgShares[i].V.Equal(newDKGShares[i].V))
	}

	// Check that the refreshed private DKG shares verify against the refreshed public DKG commits
	q := NewPubPoly(g, nil, newDKGCommits)
	for i := 0; i < n; i++ {
		require.True(test, q.Check(newDKGShares[i]))
	}

	// Recover the private polynomial
	refreshedPriPoly, err := RecoverPriPoly(g, newDKGShares, t, n)
	require.NoError(test, err)

	// Check that the secret and the corresponding (old) public commit match
	require.True(test, g.Point().Mul(refreshedPriPoly.Secret(), nil).Equal(dkgCommits[0]))
}
