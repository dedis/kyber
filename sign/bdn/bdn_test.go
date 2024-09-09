package bdn

import (
	"encoding"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/util/random"
)

var suite = bn256.NewSuiteBn256()
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

	mask, _ := NewMask([]kyber.Point{p1, p2, p3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	mask.SetBit(2, true)

	agg, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	buf, err := agg.MarshalBinary()
	require.NoError(t, err)
	ref := "1432ef60379c6549f7e0dbaf289cb45487c9d7da91fc20648f319a9fbebb23164abea76cdf7b1a3d20d539d9fe096b1d6fb3ee31bf1d426cd4a0d09d603b09f55f473fde972aa27aa991c249e890c1e4a678d470592dd09782d0fb3774834f0b2e20074a49870f039848a6b1aff95e1a1f8170163c77098e1f3530744d1826ce"
	require.Equal(t, ref, fmt.Sprintf("%x", buf))
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

	mask, _ := NewMask([]kyber.Point{public1, public2}, nil)
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
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	_, public3 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := NewMask([]kyber.Point{public1, public3, public2}, nil)
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
	suite := bn256.NewSuite()
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

	// Old scheme not resistant to the attack
	agg := scheme.AggregatePublicKeys(pubs...)
	require.NoError(t, scheme.Verify(agg, msg, sig))

	// New scheme that should detect
	mask, _ := NewMask(pubs, nil)
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

	mask, _ := NewMask([]kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	}
}

func Benchmark_BDN_BLS12381_AggregateVerify(b *testing.B) {
	suite := kilic.NewBLS12381Suite()
	schemeOnG2 := NewSchemeOnG2(suite)

	rng := random.New()
	pubKeys := make([]kyber.Point, 3000)
	privKeys := make([]kyber.Scalar, 3000)
	for i := range pubKeys {
		privKeys[i], pubKeys[i] = schemeOnG2.NewKeyPair(rng)
	}

	mask, err := NewMask(pubKeys, nil)
	require.NoError(b, err)
	for i := range pubKeys {
		require.NoError(b, mask.SetBit(i, true))
	}

	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sigs := make([][]byte, len(privKeys))
	for i, k := range privKeys {
		s, err := schemeOnG2.Sign(k, msg)
		require.NoError(b, err)
		sigs[i] = s
	}

	sig, err := schemeOnG2.AggregateSignatures(sigs, mask)
	require.NoError(b, err)
	sigb, err := sig.MarshalBinary()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk, err := schemeOnG2.AggregatePublicKeys(mask)
		require.NoError(b, err)
		require.NoError(b, schemeOnG2.Verify(pk, msg, sigb))
	}
}

func unmarshalHex[T encoding.BinaryUnmarshaler](t *testing.T, into T, s string) T {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.NoError(t, into.UnmarshalBinary(b))
	return into
}

// This tests exists to make sure we don't accidentally make breaking changes to signature
// aggregation by using checking against known aggregated signatures and keys.
func TestBDNFixtures(t *testing.T) {
	suite := bn256.NewSuite()
	schemeOnG1 := NewSchemeOnG1(suite)

	public1 := unmarshalHex(t, suite.G2().Point(), "1a30714035c7a161e286e54c191b8c68345bd8239c74925a26290e8e1ae97ed6657958a17dca12c943fadceb11b824402389ff427179e0f10194da3c1b771c6083797d2b5915ea78123cbdb99ea6389d6d6b67dcb512a2b552c373094ee5693524e3ebb4a176f7efa7285c25c80081d8cb598745978f1a63b886c09a316b1493")
	private1 := unmarshalHex(t, suite.G2().Scalar(), "49cfe5e9f4532670137184d43c0299f8b635bcacf6b0af7cab262494602d9f38")
	public2 := unmarshalHex(t, suite.G2().Point(), "603bc61466ec8762ec6de2ba9a80b9d302d08f580d1685ac45a8e404a6ed549719dc0faf94d896a9983ff23423772720e3de5d800bc200de6f7d7e146162d3183b8880c5c0d8b71ca4b3b40f30c12d8cc0679c81a47c239c6aa7e9cc2edab4a927fe865cd413c1c17e3df8f74108e784cd77dd3e161bdaf30019a55826a32a1f")
	private2 := unmarshalHex(t, suite.G2().Scalar(), "493abea4bb35b74c78ad9245f9d37883aeb6ee91f7fb0d8a8e11abf7aa2be581")
	public3 := unmarshalHex(t, suite.G2().Point(), "56118769a1f0b6286abacaa32109c1497ab0819c5d21f27317e184b6681c283007aa981cb4760de044946febdd6503ab77a4586bc29c04159e53a6fa5dcb9c0261ccd1cb2e28db5204ca829ac9f6be95f957a626544adc34ba3bc542533b6e2f5cbd0567e343641a61a42b63f26c3625f74b66f6f46d17b3bf1688fae4d455ec")
	private3 := unmarshalHex(t, suite.G2().Scalar(), "7fb0ebc317e161502208c3c16a4af890dedc3c7b275e8a04e99c0528aa6a19aa")

	sig1Exp, err := hex.DecodeString("0913b76987be19f943be23b636cab9a2484507717326bd8bbdcdbbb6b8d5eb9253cfb3597c3fa550ee4972a398813650825a871f8e0b242ae5ddbce1b7c0e2a8")
	require.NoError(t, err)
	sig2Exp, err := hex.DecodeString("21195d29b1863bca1559e24375211d1411d8a28a8f4c772870b07f4ccda2fd5e337c1315c210475c683e3aa8b87d3aed3f7255b3087daa30d1e1432dd61d7484")
	require.NoError(t, err)
	sig3Exp, err := hex.DecodeString("3c1ac80345c1733630dbdc8106925c867544b521c259f9fa9678d477e6e5d3d212b09bc0d95137c3dbc0af2241415156c56e757d5577a609293584d045593195")
	require.NoError(t, err)

	aggSigExp := unmarshalHex(t, suite.G1().Point(), "43c1d2ad5a7d71a08f3cd7495db6b3c81a4547af1b76438b2f215e85ec178fea048f93f6ffed65a69ea757b47761e7178103bb347fd79689652e55b6e0054af2")
	aggKeyExp := unmarshalHex(t, suite.G2().Point(), "43b5161ede207b9a69fc93114b0c5022b76cc22e813ba739c7e622d826b132333cd637505399963b94e393ec7f5d4875f82391620b34be1fde1f232204fa4f723935d4dbfb725f059456bcf2557f846c03190969f7b800e904d25b0b5bcbdd421c9877d443f0313c3425dfc1e7e646b665d27b9e649faadef1129f95670d70e1")

	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := schemeOnG1.Sign(private1, msg)
	require.Nil(t, err)
	require.Equal(t, sig1Exp, sig1)

	sig2, err := schemeOnG1.Sign(private2, msg)
	require.Nil(t, err)
	require.Equal(t, sig2Exp, sig2)

	sig3, err := schemeOnG1.Sign(private3, msg)
	require.Nil(t, err)
	require.Equal(t, sig3Exp, sig3)

	mask, _ := NewMask([]kyber.Point{public1, public2, public3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)
	mask.SetBit(2, true)

	aggSig, err := schemeOnG1.AggregateSignatures([][]byte{sig1, sig3}, mask)
	require.NoError(t, err)
	require.True(t, aggSigExp.Equal(aggSig))

	aggKey, err := schemeOnG1.AggregatePublicKeys(mask)
	require.NoError(t, err)
	require.True(t, aggKeyExp.Equal(aggKey))
}
