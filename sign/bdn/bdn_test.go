package bdn

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/util/random"
)

func TestBDN_AggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = AggregateSignatures(suite, [][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.Error(t, err)
}

func TestBDN_SubsetSignature(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	_, public3 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := NewMask(suite, []kyber.Point{public1, public3, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(2, true)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)
}

func TestBDN_RogueAttack(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	scheme := bls.NewSchemeOnG1(suite)
	// honest
	_, public1 := scheme.NewKeyPair(random.New())
	// attacker
	private2, public2 := scheme.NewKeyPair(random.New())

	// create a forged public-key for public1
	rogue := public1.Clone().Sub(public2, public1)

	pubs := []kyber.Point{public1, rogue}

	sig, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	// New scheme that should detect
	mask, _ := NewMask(suite, pubs, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	agg, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)
	require.Error(t, Verify(suite, agg, msg, sig))
}

func Benchmark_BDN_AggregateSigs(b *testing.B) {
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	mask, _ := NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	}
}
