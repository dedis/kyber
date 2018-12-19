package bls

import (
	"testing"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestBLS(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	err = Verify(suite, public, msg, sig)
	require.Nil(t, err)
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	sig[0] ^= 0x01
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, _ := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	_, public := NewKeyPair(suite, random.New())
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSAggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.Nil(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(t, err)
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)

	aggregatedKey := AggregatePublicKeys(suite, public1, public2)

	err = Verify(suite, aggregatedKey, msg, aggregatedSig)
	require.Nil(t, err)
}

func TestBLSFailAggregatedSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.Nil(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(t, err)
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)
	aggregatedKey := AggregatePublicKeys(suite, public1, public2)

	aggregatedSig[0] ^= 0x01
	if Verify(suite, aggregatedKey, msg, aggregatedSig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}
func TestBLSFailAggregatedKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	_, public3 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.Nil(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(t, err)
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)
	badAggregatedKey := AggregatePublicKeys(suite, public1, public2, public3)

	if Verify(suite, badAggregatedKey, msg, aggregatedSig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeyPair(suite, random.New())
	}
}

func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	private, _ := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(suite, private, msg)
	}
}

func BenchmarkBLSAggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	private1, _ := NewKeyPair(suite, random.New())
	private2, _ := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, sig1, sig2)
	}
}

func BenchmarkBLSVerifyAggregate(b *testing.B) {
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)
	sig, err := AggregateSignatures(suite, sig1, sig2)
	key := AggregatePublicKeys(suite, public1, public2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(suite, key, msg, sig)
	}
}
