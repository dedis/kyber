package bdn

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

var suite = pairing.NewSuiteBn256()
var two = suite.Scalar().Add(suite.Scalar().One(), suite.Scalar().One())
var three = suite.Scalar().Add(two, suite.Scalar().One())

// Reference test for other languages
func TestBDN_HashPointToR_BN256(t *testing.T) {
	p1 := suite.Point().Base()
	p2 := suite.Point().Mul(two, suite.Point().Base())
	p3 := suite.Point().Mul(three, suite.Point().Base())

	coefs, err := hashPointToR([]kyber.Point{p1, p2, p3})

	require.NoError(t, err)
	require.Equal(t, "35b5b395f58aba3b192fb7e1e5f2abd3", coefs[0].String())
	require.Equal(t, "14dcc79d46b09b93075266e47cd4b19e", coefs[1].String())
	require.Equal(t, "933f6013eb3f654f9489d6d45ad04eaf", coefs[2].String())
	require.Equal(t, 16, coefs[0].MarshalSize())
}

func TestBDN_AggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = AggregateSignatures(suite, [][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = AggregatePublicKeys(suite, mask)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.Error(t, err)
}

func TestBDN_SubsetSignature(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	_, public3 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public3, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(2, true)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)
}

func TestBDN_RogueAttack(t *testing.T) {
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
	mask, _ := sign.NewMask(suite, pubs, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	agg, err = AggregatePublicKeys(suite, mask)
	require.NoError(t, err)
	require.Error(t, Verify(suite, agg, msg, sig))
}

func Benchmark_BDN_AggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	}
}
