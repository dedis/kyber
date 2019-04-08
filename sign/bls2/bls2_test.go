package bls2

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

var suite = pairing.NewSuiteBn256()

func TestBLS2_HashPointToR(t *testing.T) {
	p := suite.Point().Base()
	r, err := hashPointToR(p)

	require.NoError(t, err)
	require.Equal(t, "c9f14672d945b3ff18aba35cb3f28f75", r.String())
	require.Equal(t, 16, r.MarshalSize())
}

func TestBLS2_AggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, []kyber.Point{public1, public2})
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys([]kyber.Point{public1, public2})

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	aggregatedKey, err = AggregatePublicKeys([]kyber.Point{public2})

	err = Verify(suite, aggregatedKey, msg, sig)
	require.Error(t, err)
}

func Benchmark_BLS2_AggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, [][]byte{sig1, sig2}, []kyber.Point{public1, public2})
	}
}
