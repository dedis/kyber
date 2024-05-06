package bls

import (
	"crypto/rand"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/util/random"
)

func PrepareBLS(numSigs int) (suite *bn256.Suite, scheme sign.AggregatableScheme,
	publics []kyber.Point, privates []kyber.Scalar, msgs [][]byte, sigs [][]byte) {
	suite = bn256.NewSuite()
	scheme = NewSchemeOnG1(suite)

	publics = make([]kyber.Point, numSigs)
	privates = make([]kyber.Scalar, numSigs)
	msgs = make([][]byte, numSigs)
	sigs = make([][]byte, numSigs)
	for i := 0; i < numSigs; i++ {
		private, public := scheme.NewKeyPair(random.New())
		publics[i] = public
		privates[i] = private
		msg := make([]byte, 64, 64)
		rand.Read(msg)
		msgs[i] = msg
		sig, err := scheme.Sign(private, msg)
		if err != nil {
			panic(err)
		}
		sigs[i] = sig
	}
	return
}

func BenchCreateKeys(b *testing.B, scheme sign.AggregatableScheme, n int) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			scheme.NewKeyPair(random.New())
		}
	}
}

func BenchSign(b *testing.B, scheme sign.AggregatableScheme, msg []byte, privates []kyber.Scalar) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, private := range privates {
			scheme.Sign(private, msg)
		}
	}
}

func BenchVerify(b *testing.B, sigs [][]byte, scheme sign.AggregatableScheme, suite *bn256.Suite, publics []kyber.Point, msgs [][]byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSig, _ := scheme.AggregateSignatures(sigs...)
		BatchVerify(suite, publics, msgs, aggregateSig)
	}
}
