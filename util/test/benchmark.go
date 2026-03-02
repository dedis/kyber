package test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bls12381/circl"
	"go.dedis.ch/kyber/v4/sign"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/util/random"
)

func PrepareBLS(numSigs int) (scheme sign.Scheme,
	publics []kyber.Point, privates []kyber.Scalar, msgs [][]byte, sigs [][]byte) {
	suite := circl.NewSuite()
	scheme = bls.NewSchemeOnG1(suite)

	publics = make([]kyber.Point, numSigs)
	privates = make([]kyber.Scalar, numSigs)
	msgs = make([][]byte, numSigs)
	sigs = make([][]byte, numSigs)
	for i := 0; i < numSigs; i++ {
		private, public := scheme.NewKeyPair(random.New())
		publics[i] = public
		privates[i] = private
		msg := make([]byte, 64)
		_, err := rand.Read(msg)
		if err != nil {
			panic(err)
		}
		msgs[i] = msg
		sig, err := scheme.Sign(private, msg)
		if err != nil {
			panic(err)
		}
		sigs[i] = sig
	}
	return scheme, publics, privates, msgs, sigs
}

func BenchCreateKeys(b *testing.B, scheme sign.Scheme, n int) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			scheme.NewKeyPair(random.New())
		}
	}
}

func BenchSign(b *testing.B, scheme sign.Scheme, msg []byte, privates []kyber.Scalar) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, private := range privates {
			_, err := scheme.Sign(private, msg)
			require.NoError(b, err)
		}
	}
}

func BLSBenchVerify(b *testing.B, sigs [][]byte, scheme sign.Scheme,
	publics []kyber.Point, msgs [][]byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, p := range publics {
			err := scheme.Verify(p, msgs[j], sigs[j])
			require.NoError(b, err)
		}
	}
}
