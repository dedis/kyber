package test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/util/random"
)

// ThresholdTest performs a simple check on a threshold scheme implementation
func ThresholdTest(test *testing.T, keyGroup kyber.Group, scheme sign.ThresholdScheme) {
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	n := 10
	t := n/2 + 1
	test.Run("Correct sharing and recovering", func(tt *testing.T) {
		secret := keyGroup.Scalar().Pick(random.New())
		priPoly := share.NewPriPoly(keyGroup, t, secret, random.New())
		pubPoly := priPoly.Commit(keyGroup.Point().Base())
		sigShares := make([][]byte, 0)
		for _, x := range priPoly.Shares(n) {
			sig, err := scheme.Sign(x, msg)
			require.Nil(tt, err)
			require.Nil(tt, scheme.VerifyPartial(pubPoly, msg, sig))
			idx, err := scheme.IndexOf(sig)
			require.NoError(tt, err)
			require.Equal(tt, x.I, idx)
			sigShares = append(sigShares, sig)
			idx, err = scheme.IndexOf(sig)
			require.NoError(tt, err)
			require.Equal(tt, idx, x.I)
		}
		sig, err := scheme.Recover(pubPoly, msg, sigShares, t, n)
		require.Nil(tt, err)
		err = scheme.VerifyRecovered(pubPoly.Commit(), msg, sig)
		require.Nil(tt, err)
	})

	test.Run("Invalid PublicKey", func(tt *testing.T) {
		secret := keyGroup.Scalar().Pick(random.New())
		priPoly := share.NewPriPoly(keyGroup, t, secret, random.New())
		pubPoly := priPoly.Commit(keyGroup.Point().Base())
		sigShares := make([][]byte, 0)
		for _, x := range priPoly.Shares(n) {
			sig, err := scheme.Sign(x, msg)
			require.Nil(tt, err)
			require.Nil(tt, scheme.VerifyPartial(pubPoly, msg, sig))
			sigShares = append(sigShares, sig)
		}
		sig, err := scheme.Recover(pubPoly, msg, sigShares, t, n)
		require.Nil(tt, err)
		err = scheme.VerifyRecovered(keyGroup.Point().Pick(random.New()), msg, sig)
		require.Error(tt, err)
	})

	test.Run("Invalid PartialSig", func(tt *testing.T) {
		secret := keyGroup.Scalar().Pick(random.New())
		priPoly := share.NewPriPoly(keyGroup, t, secret, random.New())
		pubPoly := priPoly.Commit(keyGroup.Point().Base())
		fakeSecret := keyGroup.Scalar().Pick(random.New())
		fakePriPoly := share.NewPriPoly(keyGroup, t, fakeSecret, random.New())
		for _, x := range fakePriPoly.Shares(n) {
			sig, err := scheme.Sign(x, msg)
			require.Nil(tt, err)
			require.Error(tt, scheme.VerifyPartial(pubPoly, msg, sig))
		}

		weirdSig := []byte("ain't no sunshine when she's gone")
		require.Error(tt, scheme.VerifyPartial(pubPoly, msg, weirdSig))
		_, err := scheme.IndexOf(weirdSig)
		require.Error(tt, err)
		smallSig := []byte{1, 2, 3}
		_, err = scheme.IndexOf(smallSig)
		require.Error(tt, err)

	})
	test.Run("Invalid Recovered Sig", func(tt *testing.T) {
		secret := keyGroup.Scalar().Pick(random.New())
		priPoly := share.NewPriPoly(keyGroup, t, secret, random.New())
		pubPoly := priPoly.Commit(keyGroup.Point().Base())
		fakeSecret := keyGroup.Scalar().Pick(random.New())
		fakePriPoly := share.NewPriPoly(keyGroup, t, fakeSecret, random.New())
		fakeShares := fakePriPoly.Shares(n)
		fakeSigShares := make([][]byte, 0)
		fakePubPoly := fakePriPoly.Commit(keyGroup.Point().Base())
		for i := 0; i < n; i++ {
			fakeSig, _ := scheme.Sign(fakeShares[i], msg)
			fakeSigShares = append(fakeSigShares, fakeSig)
		}
		fakeSig, err := scheme.Recover(fakePubPoly, msg, fakeSigShares, t, n)
		require.Nil(tt, err)
		err = scheme.VerifyRecovered(pubPoly.Commit(), msg, fakeSig)
		require.Error(tt, err)
	})
}
