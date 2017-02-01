package sha3

import (
	"testing"

	"gopkg.in/dedis/crypto.v0/test"
)

func TestAES(t *testing.T) {
	test.CipherTest(t, NewCipher224)
}
