package bls

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
	"testing"
)

func TestBLSBatchVerify(t *testing.T) {
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg1)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg2)
	require.Nil(t, err)
	aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
	require.Nil(t, err)

	err = BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig)
	require.Nil(t, err)
}

func TestBLSFailBatchVerify(t *testing.T) {
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg1)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg2)
	require.Nil(t, err)

	t.Run("fails with a bad signature", func(t *testing.T) {
		aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
		require.Nil(t, err)
		msg2[0] ^= 0x01
		if BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

	t.Run("fails with a duplicate msg", func(t *testing.T) {
		private3, public3 := scheme.NewKeyPair(random.New())
		sig3, err := scheme.Sign(private3, msg1)
		require.Nil(t, err)
		aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2, sig3)
		require.Nil(t, err)

		if BatchVerify(suite, []kyber.Point{public1, public2, public3}, [][]byte{msg1, msg2, msg1}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})
}

func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.NewKeyPair(random.New())
	}
}

func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scheme.Sign(private, msg)
		require.Nil(b, err)
	}
}

func BenchmarkBLSAggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, _ := scheme.NewKeyPair(random.New())
	private2, _ := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(b, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scheme.AggregateSignatures(sig1, sig2)
		require.Nil(b, err)
	}
}

func BenchmarkBLSVerifyAggregate(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(b, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(b, err)
	sig, err := scheme.AggregateSignatures(sig1, sig2)
	key := scheme.AggregatePublicKeys(public1, public2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := scheme.Verify(key, msg, sig)
		require.Nil(b, err)
	}
}

func BenchmarkBLSVerifyBatchVerify(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	numSigs := 100
	privates := make([]kyber.Scalar, numSigs)
	publics := make([]kyber.Point, numSigs)
	msgs := make([][]byte, numSigs)
	sigs := make([][]byte, numSigs)
	for i := 0; i < numSigs; i++ {
		private, public := scheme.NewKeyPair(random.New())
		privates[i] = private
		publics[i] = public
		msg := make([]byte, 64, 64)
		_, err := rand.Read(msg)
		require.Nil(b, err)
		msgs[i] = msg
		sig, err := scheme.Sign(private, msg)
		require.Nil(b, err)
		sigs[i] = sig
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSig, _ := scheme.AggregateSignatures(sigs...)
		err := BatchVerify(suite, publics, msgs, aggregateSig)
		require.Nil(b, err)
	}
}
