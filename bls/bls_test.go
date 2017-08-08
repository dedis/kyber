package bls

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dedis/kyber/pbc"
	"github.com/dedis/kyber/random"
)

func TestBLSSig(t *testing.T) {
	s := pbc.NewPairingFp382_1()
	sk, pk := NewKeyPair(s, random.Stream)
	msg := []byte("hello world")

	sig := Sign(s, sk, msg)
	require.Nil(t, Verify(s, pk, msg, sig))

	wrongMsg := []byte("evil message")
	require.Error(t, Verify(s, pk, msg, wrongMsg))
}
