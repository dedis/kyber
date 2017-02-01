package aes

import (
	"testing"

	"gopkg.in/dedis/crypto.v0/test"
)

func TestAES(t *testing.T) {
	test.CipherTest(t, NewCipher128)
}
