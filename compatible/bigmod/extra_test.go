package bigmod_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"filippo.io/bigmod"
)

// TestLinkWithStdlib ensures this package can be linked with the standard
// library package crypto/internal/bigmod, which might have duplicate global
// symbol names in the assembly files. See Issue 1.
func TestLinkWithStdlib(t *testing.T) {
	bigmod.NewNat()
	k, _ := rsa.GenerateKey(rand.Reader, 512)
	rsa.SignPSS(rand.Reader, k, crypto.SHA256, make([]byte, 32), nil)
}
