package bdn

import (
	"fmt"
	"testing"

	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

// Reference test for other languages
func TestBDN_HashPointToR_BN256(t *testing.T) {
	suite := bn256.NewSuiteBn256()
	schemeOnG1 := NewSchemeOnG1(suite)
	two := suite.Scalar().Add(suite.Scalar().One(), suite.Scalar().One())
	three := suite.Scalar().Add(two, suite.Scalar().One())

	p1 := suite.Point().Base()
	p2 := suite.Point().Mul(two, suite.Point().Base())
	p3 := suite.Point().Mul(three, suite.Point().Base())

	coefs, err := hashPointToR([]kyber.Point{p1, p2, p3})

	require.NoError(t, err)
	require.Equal(t, "35b5b395f58aba3b192fb7e1e5f2abd3", coefs[0].String())
	require.Equal(t, "14dcc79d46b09b93075266e47cd4b19e", coefs[1].String())
	require.Equal(t, "933f6013eb3f654f9489d6d45ad04eaf", coefs[2].String())
	require.Equal(t, 16, coefs[0].MarshalSize())

	mask, _ := sign.NewMask(suite, []kyber.Point{p1, p2, p3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	mask.SetBit(2, true)

	agg, err := schemeOnG1.AggregatePublicKeys(mask)
	require.NoError(t, err)

	buf, err := agg.MarshalBinary()
	require.NoError(t, err)
	ref := "1432ef60379c6549f7e0dbaf289cb45487c9d7da91fc20648f319a9fbebb23164abea76cdf7b1a3d20d539d9fe096b1d6fb3ee31bf1d426cd4a0d09d603b09f55f473fde972aa27aa991c249e890c1e4a678d470592dd09782d0fb3774834f0b2e20074a49870f039848a6b1aff95e1a1f8170163c77098e1f3530744d1826ce"
	require.Equal(t, ref, fmt.Sprintf("%x", buf))
}

var testsOnSchemes = []struct {
	name string
	test func(t *testing.T, suite pairing.Suite, scheme *Scheme)
}{
	{"aggregateSignatures", aggregateSignatures},
	{"subsetSignature", subsetSignature},
	{"rogueAttack", rogueAttack},
}

func TestBDN(t *testing.T) {
	run := func(name string, suite pairing.Suite, schemeGen func(pairing.Suite) *Scheme) {
		for _, ts := range testsOnSchemes {
			t.Run(name+"/"+ts.name, func(t *testing.T) {
				ts.test(t, suite, schemeGen(suite))
			})
		}
	}

	run("bn256/G1", bn256.NewSuite(), NewSchemeOnG1)
	//run("bn256/G2", bn256.NewSuite(), NewSchemeOnG2) // G2 does not support hash to point https://github.com/dedis/kyber/pull/428
	run("bls12/G1", bls12381.NewBLS12381Suite(), NewSchemeOnG1)
	run("bls12/G2", bls12381.NewBLS12381Suite(), NewSchemeOnG2)

}

func aggregateSignatures(t *testing.T, suite pairing.Suite, scheme *Scheme) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.NoError(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = scheme.AggregateSignatures([][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := scheme.AggregateSignatures([][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = scheme.Verify(aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)

	err = scheme.Verify(aggregatedKey, msg, sig)
	require.Error(t, err)
}

func subsetSignature(t *testing.T, suite pairing.Suite, scheme *Scheme) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	_, public3 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.NoError(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public3, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(2, true)

	aggregatedSig, err := scheme.AggregateSignatures([][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = scheme.Verify(aggregatedKey, msg, sig)
	require.NoError(t, err)
}

func rogueAttack(t *testing.T, suite pairing.Suite, scheme *Scheme) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	// honest
	_, public1 := scheme.NewKeyPair(random.New())
	// attacker
	private2, public2 := scheme.NewKeyPair(random.New())

	// create a forged public-key for public1
	rogue := public1.Clone().Sub(public2, public1)

	pubs := []kyber.Point{public1, rogue}

	sig, err := scheme.Sign(private2, msg)
	require.NoError(t, err)

	// Old scheme not resistant to the attack
	agg := scheme.blsScheme.AggregatePublicKeys(pubs...)
	require.NoError(t, scheme.Verify(agg, msg, sig))

	// New scheme that should detect
	mask, _ := sign.NewMask(suite, pubs, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	agg, err = scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)
	require.Error(t, scheme.Verify(agg, msg, sig))
}

func Benchmark_BDN_AggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	schemeOnG1 := NewSchemeOnG1(suite)
	private1, public1 := schemeOnG1.NewKeyPair(random.New())
	private2, public2 := schemeOnG1.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := schemeOnG1.Sign(private1, msg)
	require.Nil(b, err)
	sig2, err := schemeOnG1.Sign(private2, msg)
	require.Nil(b, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		schemeOnG1.AggregateSignatures([][]byte{sig1, sig2}, mask)
	}
}

func TestBDNDeprecatedAPIs(t *testing.T) {
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
