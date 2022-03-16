package tbls

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 10
	t := n/2 + 1
	secret := suite.G2().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	require.Nil(test, err)

	// tests for privates in order
	n = 3
	t = n/2 + 1
	priv1 := suite.G2().Scalar().Pick(suite.RandomStream())
	priv2 := suite.G2().Scalar().Pick(suite.RandomStream())

	g2 := suite.G2()
	base := suite.G2().Point().Base()
	commits := make([]kyber.Point, t)
	commits[0] = g2.Point().Mul(priv2, base)
	commits[1] = g2.Point().Mul(priv1, base)
	pubPoly = share.NewPubPoly(suite.G2(), suite.G2().Point().Base(), commits)

	x0 := g2.Scalar().SetInt64(1)
	x1 := g2.Scalar().SetInt64(2)
	x2 := g2.Scalar().SetInt64(3)
	xScalars := []kyber.Scalar{x0, x1, x2}

	shares := make([]*share.PriShare, n)
	for i := range shares {
		zero := g2.Scalar().Zero()
		zero.Mul(zero, xScalars[i])
		zero.Add(zero, priv1)
		shares[i] = &share.PriShare{i, zero}
	}

	for i := range shares {
		shares[i].V.Mul(shares[i].V, xScalars[i])
		shares[i].V.Add(shares[i].V, priv2)
		shares[i] = &share.PriShare{i, shares[i].V}
	}

	sigShares = make([][]byte, 0)
	for _, x := range shares {
		sig, err := Sign(suite, x, msg)
		if err != nil {
			log.Panicln(err)
		}
		sigShares = append(sigShares, sig)
	}
	sig, err = Recover(suite, pubPoly, msg, sigShares, t, n)
	if err != nil {
		log.Panicln(err)
	}
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	if err != nil {
		log.Panicln(err)
	}
}
