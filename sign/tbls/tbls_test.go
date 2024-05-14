package tbls

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/internal/test"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

func TestTBLS(test *testing.T) {
	TBLSRoutine(test, []byte("Hello threshold Boneh-Lynn-Shacham"), 10)
}

func FuzzTBLS(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte, n int) {
		if (n < 1) || (n > 100) {
			t.Skip("n must be between 1 and 100")
		}
		if (len(msg) < 1) || (len(msg) > 1000) {
			t.Skip("msg must have byte length between 1 and 1000")
		}
		TBLSRoutine(t, msg, n)
	})
}

func TBLSRoutine(test *testing.T, msg []byte, n int) {
	// Use a deterministic seed for the random stream
	stream := blake2xb.New(msg)
	suite := bn256.NewSuiteRand(stream)
	scheme := NewThresholdSchemeOnG1(suite)
	th := n/2 + 1

	secret := suite.G1().Scalar().Pick(stream)
	priPoly := share.NewPriPoly(suite.G2(), th, secret, stream)
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)

	for _, x := range priPoly.Shares(n) {
		sig, err := scheme.Sign(x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}

	sig, err := scheme.Recover(pubPoly, msg, sigShares, th, n)
	require.Nil(test, err)

	err = scheme.VerifyRecovered(pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}

func TestBN256(t *testing.T) {
	suite := bn256.NewSuite()
	scheme := NewThresholdSchemeOnG1(suite)
	test.ThresholdTest(t, suite.G2(), scheme)
}
