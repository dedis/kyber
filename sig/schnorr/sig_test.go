package schnorr

import (
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/sig"
	"github.com/dedis/crypto/suites"
	"github.com/dedis/crypto/test"
	"testing"
)

func TestSignVerify(t *testing.T) {
	suite := suites.Default
	rand := random.Stream
	newKey := func() sig.SecretKey {
		return SecretKey(suite, rand)
	}
	test.TestSig(t, newKey)
}
