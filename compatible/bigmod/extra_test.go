package bigmod_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/compatible/bigmod"
)

// TestLinkWithStdlib ensures this package can be linked with the standard
// library package crypto/internal/bigmod, which might have duplicate global
// symbol names in the assembly files. See Issue 1.
func TestLinkWithStdlib(t *testing.T) {
	bigmod.NewNat()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, make([]byte, 32), nil)
	require.NoError(t, err)
}
