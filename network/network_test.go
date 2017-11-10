package network

import (
	"testing"

	"github.com/dedis/kyber/group/edwards25519"

	"github.com/dedis/onet/log"
)

var testSuite = edwards25519.NewAES128SHA256Ed25519()

func TestMain(m *testing.M) {
	log.MainTest(m)
}
