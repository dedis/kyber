package tbls

import (
	"testing"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/bls"
	"github.com/stretchr/testify/require"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewTresholdSchemeOnG1(suite)
	n := 10
	t := n/2 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := scheme.Sign(x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := scheme.Recover(pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	err = bls.NewSchemeOnG1(suite).Verify(pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}
