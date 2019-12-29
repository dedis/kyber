package test

import (
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

// ThresholdTest performs a simple check on a threshold scheme implementation
func ThresholdTest(test *testing.T, keyGroup kyber.Group, scheme sign.ThresholdScheme) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	n := 10
	t := n/2 + 1
	secret := keyGroup.Scalar().Pick(random.New())
	priPoly := share.NewPriPoly(keyGroup, t, secret, random.New())
	pubPoly := priPoly.Commit(keyGroup.Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := scheme.Sign(x, msg)
		require.Nil(test, err)
		require.Nil(test, scheme.VerifyPartial(pubPoly, msg, sig))
		sigShares = append(sigShares, sig)
	}
	sig, err := scheme.Recover(pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	err = scheme.VerifyRecovered(pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}
