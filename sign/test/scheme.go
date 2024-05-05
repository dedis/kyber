package test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/util/random"
)

// SchemeTesting tests a scheme with simple checks
func SchemeTesting(t *testing.T, s sign.Scheme) {
	t.Run("Regular signing & verifying", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private, public := s.NewKeyPair(random.New())
		sig, err := s.Sign(private, msg)
		require.Nil(tt, err)
		err = s.Verify(public, msg, sig)
		require.Nil(tt, err)
	})
	t.Run("Invalid signature", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private, public := s.NewKeyPair(random.New())
		sig, err := s.Sign(private, msg)
		require.Nil(tt, err)
		sig[0] ^= 0x01
		if s.Verify(public, msg, sig) == nil {
			tt.Fatal("verification succeeded unexpectedly")
		}
	})
	t.Run("Invalid Key", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private, _ := s.NewKeyPair(random.New())
		sig, err := s.Sign(private, msg)
		require.Nil(tt, err)
		_, public := s.NewKeyPair(random.New())
		if s.Verify(public, msg, sig) == nil {
			tt.Fatal("verification succeeded unexpectedly")
		}
	})
}

// AggregationTesting test an aggrgatable scheme
func AggregationTesting(t *testing.T, s sign.AggregatableScheme) {
	t.Run("Aggregation valid", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private1, public1 := s.NewKeyPair(random.New())
		private2, public2 := s.NewKeyPair(random.New())
		sig1, err := s.Sign(private1, msg)
		require.Nil(tt, err)
		sig2, err := s.Sign(private2, msg)
		require.Nil(tt, err)
		aggregatedSig, err := s.AggregateSignatures(sig1, sig2)
		require.Nil(tt, err)
		aggregatedKey := s.AggregatePublicKeys(public1, public2)

		err = s.Verify(aggregatedKey, msg, aggregatedSig)
		require.Nil(tt, err)
	})
	t.Run("Aggregation with invalid sig", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private1, public1 := s.NewKeyPair(random.New())
		private2, public2 := s.NewKeyPair(random.New())
		sig1, err := s.Sign(private1, msg)
		require.Nil(tt, err)
		sig2, err := s.Sign(private2, msg)
		require.Nil(tt, err)
		aggregatedSig, err := s.AggregateSignatures(sig1, sig2)
		require.Nil(tt, err)
		aggregatedKey := s.AggregatePublicKeys(public1, public2)

		aggregatedSig[0] ^= 0x01
		if s.Verify(aggregatedKey, msg, aggregatedSig) == nil {
			tt.Fatal("bls: verification succeeded unexpectedly")
		}
	})

	t.Run("Aggregation with invalid public", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private1, public1 := s.NewKeyPair(random.New())
		private2, public2 := s.NewKeyPair(random.New())
		_, public3 := s.NewKeyPair(random.New())
		sig1, err := s.Sign(private1, msg)
		require.Nil(tt, err)
		sig2, err := s.Sign(private2, msg)
		require.Nil(tt, err)
		aggregatedSig, err := s.AggregateSignatures(sig1, sig2)
		require.Nil(tt, err)
		badAggregatedKey := s.AggregatePublicKeys(public1, public2, public3)

		if s.Verify(badAggregatedKey, msg, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})
}
