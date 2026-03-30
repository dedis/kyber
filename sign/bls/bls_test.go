//go:build !constantTime

package bls

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

func TestBLS(t *testing.T) {
	suite := bn256.NewSuite()
	msg := []byte("Hello Boneh-Lynn-Shacham")
	BLSRoutine(t, msg, suite)
}

func FuzzBLS(f *testing.F) {
	suite := bn256.NewSuite()
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) < 1 || len(msg) > 1000 {
			t.Skip("msg must have byte length between 1 and 1000")
		}
		BLSRoutine(t, msg, suite)
	})
}

func BLSRoutine(t *testing.T, msg []byte, suite *bn256.Suite) {
	scheme := NewSchemeOnG1(suite)
	private, public := scheme.NewKeyPair(blake2xb.New(msg))
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	err = scheme.Verify(public, msg, sig)
	require.Nil(t, err)
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, public := scheme.NewKeyPair(random.New())
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	sig[0] ^= 0x01
	if scheme.Verify(public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	_, public := scheme.NewKeyPair(random.New())
	if scheme.Verify(public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	b.ResetTimer()
	for b.Loop() {
		scheme.NewKeyPair(random.New())
	}
}

func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	b.ResetTimer()
	for b.Loop() {
		_, err := scheme.Sign(private, msg)
		require.Nil(b, err)
	}
}
