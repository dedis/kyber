package share

import (
	"fmt"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretRecovery(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	poly := NewPriPoly(g, t, nil, g.RandomStream())
	shares := poly.Shares(n)

	recovered, err := RecoverSecret(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(poly.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}
}

func TestSecretRecoverySub2(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	poly := NewPriPoly(g, t, nil, g.RandomStream())
	pubPoly := poly.Commit(nil)

	oldShares := make([]*PriShare, n)
	newShares := make([]*PriShare, n)

	oldShares = poly.Shares(n)

	// start sub-sharing
	subpolys := make([]*PriPoly, n)
	subshares := make([][]*PriShare, n)

	subPubPolys := make([]*PubPoly, n)
	subPubCoefs := make([][]kyber.Point, n)
	subPubShares := make([][]*PubShare, n)

	// for each share, we compute a set of sub-shares
	for i := 0; i < n; i++ {
		// create subshares of the share of node i
		subpolys[i] = NewPriPoly(g, t, oldShares[i].V, g.RandomStream())
		subshares[i] = subpolys[i].Shares(n)

		subPubPolys[i] = subpolys[i].Commit(nil)
		subPubShares[i] = subPubPolys[i].Shares(n)
		_, subPubCoefs[i] = subPubPolys[i].Info()

		for j := 0; j < n; j++ {
			// local check
			require.True(test, subPubPolys[i].Eval(j).V.Equal(g.Point().Mul(subshares[i][j].V, nil)))
		}

		//  small test
		// subshare * G == subPubShare
		for j := 0; j < n; j++ {
			require.Equal(test, subPubShares[i][j].V.String(), g.Point().Mul(subshares[i][j].V, nil).String())
		}
	}

	// general shares test
	// generate all s_i
	sis := make([]*PubShare, n)
	for i := 0; i < n; i++ {
		sis[i] = pubPoly.Eval(i)
		// check that the commitmennt shares received is equal to the one
		// generated
		require.True(test, sis[i].V.Equal(subPubPolys[i].Commit()))
	}
	gk, err := RecoverCommit(g, sis, t, n)
	require.NoError(test, err)
	require.True(test, gk.Equal(pubPoly.Commit()))

	pubShares := make([]*PubShare, n)
	// give respective sub-shares to each node
	for j := 0; j < n; j++ {
		tmpshares := make([]*PriShare, n)
		tmpPubShares := make([]*PubShare, n)
		// take all j-th in the slice of sub-shares of everyone
		for k := 0; k < n; k++ {
			tmpshares[k] = subshares[k][j]
			tmpshares[k].I = k // because this time, the creator has the index

			tmpPubShares[k] = subPubShares[k][j]
			tmpPubShares[k].I = k
		}
		for j := 0; j < n; j++ {
			require.Equal(test, tmpPubShares[j].V.String(), g.Point().Mul(tmpshares[j].V, nil).String())
		}
		// reconstruct the new share
		sec, err := RecoverSecret(g, tmpshares, t, n)
		require.NoError(test, err)
		newShares[j] = &PriShare{I: j, V: sec}

		// reconstruct new pub share
		pub, err := RecoverCommit(g, tmpPubShares, t, n)
		require.NoError(test, err)
		pubShares[j] = &PubShare{I: j, V: pub}

		// Check if the commitment of the recovered secret is equal to the
		// recovered public share
		require.Equal(test, g.Point().Mul(sec, nil).String(), pub.String())
	}

	// check if it reconstructs to same secret
	recovered, err := RecoverSecret(g, newShares, t, n)
	require.NoError(test, err)
	require.Equal(test, recovered.String(), poly.Secret().String())

	// check if you can reconstruct the public polynomial
	// only the commitment
	pubRecovered, err := RecoverCommit(g, pubShares, t, n)
	require.NoError(test, err)
	require.Equal(test, g.Point().Mul(recovered, nil).String(), pubRecovered.String())

	// all of the coefficients
	pubPolyRecovered, err := RecoverPubPoly(g, pubShares, t, n)
	require.NoError(test, err)
	require.NotNil(test, pubPolyRecovered)
	//require.True(test, pubPolyRecovered.Check(newShares[0]))

	// -----
	// let's reconstruct the public polynomial coefficients by coefficients
	finalCoeffs := make([]kyber.Point, t)
	// for each coefficients in the final polynomial
	for i := 0; i < t; i++ {
		//  reconstruct one by taking the i-th coefficients of all polynomials
		tmpSlice := make([]*PubShare, n)
		for j := 0; j < n; j++ {
			tmpSlice[j] = &PubShare{I: j, V: subPubCoefs[j][i]}
		}
		// lagrange interpolate those coefficients
		finalCoeff, err := RecoverCommit(g, tmpSlice, t, n)
		require.NoError(test, err)
		finalCoeffs[i] = finalCoeff
	}
	finalPubPoly := NewPubPoly(g, g.Point().Base(), finalCoeffs)
	require.Equal(test, g.Point().Mul(recovered, nil).String(), finalPubPoly.Commit().String())
	for i := 0; i < n; i++ {
		require.True(test, finalPubPoly.Check(newShares[i]))
	}

	// ----

	//require.Equal(test, g.Point().Mul(recovered, nil).String(), pubPolyRecovered.Commit().String())
	//share := pubPolyRecovered.Eval(0)
	//require.Equal(test, g.Point().Mul(newShares[0].V, nil), share.V)
	//require.True(test, pubPolyRecovered.Check(newShares[0]))

}

func TestSecretRecoverySub(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	// each make their own polynomial
	polys := make([]*PriPoly, n)
	individualShares := make([][]*PriShare, n)
	finalShares := make([]*PriShare, n)
	secret := g.Scalar().Zero()
	var priPoly *PriPoly
	var pubPoly *PubPoly
	var err error
	for i := 0; i < n; i++ {
		polys[i] = NewPriPoly(g, t, nil, g.RandomStream())
		individualShares[i] = polys[i].Shares(n)
		secret = secret.Add(secret, polys[i].Secret())
		if priPoly == nil {
			priPoly = polys[i]
			continue
		}
		priPoly, err = priPoly.Add(polys[i])
		require.NoError(test, err)
	}
	pubPoly = priPoly.Commit(nil)

	// compute final share (of DKG)
	for i := 0; i < n; i++ {
		finalShare := g.Scalar().Zero()
		for j := 0; j < n; j++ {
			finalShare = finalShare.Add(finalShare, individualShares[j][i].V)
		}
		finalShares[i] = &PriShare{I: i, V: finalShare}
	}

	// test if DKG is correct
	recovered, err := RecoverSecret(g, finalShares, t, n)
	require.NoError(test, err)
	require.Equal(test, recovered.String(), secret.String())

	// start sub-sharing
	subpolys := make([]*PriPoly, n)
	subPubPolys := make([]*PubPoly, n)
	subshares := make([][]*PriShare, n)
	subPubShares := make([][]*PubShare, n)
	// for each final share, we compute a set of sub-shares
	for i := 0; i < n; i++ {
		// create subshares of the share of node i
		subpolys[i] = NewPriPoly(g, t, finalShares[i].V, g.RandomStream())
		subshares[i] = subpolys[i].Shares(n)
		// subshares of the polynomial
		subPubPolys[i] = subpolys[i].Commit(nil)
		subPubShares[i] = subPubPolys[i].Shares(n)
	}

	newShares := make([]*PriShare, n)
	newPubShares := make([]*PubShare, n)
	// give respective sub-shares to each node
	for j := 0; j < n; j++ {
		tmpshares := make([]*PriShare, n)
		tmpPubShares := make([]*PubShare, n)
		// take all j-th in the slice of sub-shares of everyone
		for k := 0; k < n; k++ {
			tmpshares[k] = subshares[k][j]
			tmpshares[k].I = k // because this time, the creator has the index
			//fmt.println("shares:", tmpshares[j].i)

			tmpPubShares[k] = subPubShares[k][j]
			tmpPubShares[k].I = k
		}
		// reconstruct the new share
		sec, err := RecoverSecret(g, tmpshares, t, n)
		require.NoError(test, err)
		pub, err := RecoverCommit(g, tmpPubShares, t, n)
		require.NoError(test, err)
		newShares[j] = &PriShare{I: j, V: sec}
		newPubShares[j] = &PubShare{I: j, V: pub}

		// check
		p := g.Point().Mul(newShares[j].V, nil)
		require.Equal(test, p.String(), pubPoly.Eval(j).V.String())
		//require.Equal(test, p.String(), newPubShares[j].V.String())
	}

	// check if it reconstructs to same secret
	recovered, err = RecoverSecret(g, newShares, t, n)
	require.NoError(test, err)
	require.Equal(test, recovered.String(), secret.String())

	// check public polynomial
	pubRecovered, err := RecoverPubPoly(g, newPubShares, t, n)
	require.NoError(test, err)
	_, c3 := pubRecovered.Info()
	fmt.Println(c3)
	// check if has the same public key
	require.Equal(test, g.Point().Mul(recovered, nil).String(), c3[0].String())
	// check if a new share can validate against
	idx := 2
	pubShare := g.Point().Mul(newShares[idx].V, nil)
	/*pubEval := pubRecovered.Eval(idx)*/
	/*require.Equal(test, pubShare.String(), pubEval.V.String())*/
	pubEval := pubPoly.Eval(idx)
	require.Equal(test, pubShare.String(), pubEval.V.String())

	recoveredPoly, err := RecoverPriPoly(g, newShares, t, n)
	require.NoError(test, err)
	pubRecovered2 := recoveredPoly.Commit(g.Point().Base())
	_, c1 := pubRecovered2.Info()
	fmt.Println(c1)
	_, c2 := pubPoly.Info()
	fmt.Println(c2)

	// construct new distributed polynomial
	// each node generates its own public shares of each "subshare" polynomial he
	// received and then reconstruct the public polynomial
	//pubShares := make([][]*PubShare, n)
	//for i := 0; i < n; i++ {

	//}
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
