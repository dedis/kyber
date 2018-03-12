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
	sig := Sign(suite, private, msg)
	err := Verify(suite, public, msg, sig)
	require.Nil(t, err)
}

func TestBLSFail(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	sig := Sign(suite, private, msg)
	sig[0] ^= 0x01
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}
