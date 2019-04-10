package bls2

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

var suite = pairing.NewSuiteBn256()

// Reference test for other languages
func TestBLS2_HashPointToR(t *testing.T) {
	p := suite.Point().Base()
	b, err := p.MarshalBinary()
	require.NoError(t, err)

	r, err := hashPointToR(b, [][]byte{b})

	require.NoError(t, err)
	require.Equal(t, "ff7c62b770491a3ac511ff12f25621cb", r.String())
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

func TestBLS2_RogueAttack(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	// honest
	_, public1 := NewKeyPair(suite, random.New())
	// attacker
	private2, public2 := NewKeyPair(suite, random.New())

	// create a forged public-key for public1
	rogue := public1.Clone().Sub(public2, public1)

	pubs := []kyber.Point{public1, rogue}

	sig, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	// Old scheme not resistant to the attack
	agg := bls.AggregatePublicKeys(suite, pubs...)
	require.NoError(t, bls.Verify(suite, agg, msg, sig))

	// New scheme that should detect
	agg, err = AggregatePublicKeys(pubs)
	require.NoError(t, err)
	require.Error(t, Verify(suite, agg, msg, sig))
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
