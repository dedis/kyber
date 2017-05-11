package aes

import (
	"testing"

	"github.com/dedis/kyber/test"
)

func TestAES(t *testing.T) {
	test.CipherTest(t, NewCipher128)
}
