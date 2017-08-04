package network

import (
	"testing"

	"gopkg.in/dedis/kyber.v1/group/edwards25519"

	"gopkg.in/dedis/onet.v2/log"
)

var testSuite = edwards25519.NewAES128SHA256Ed25519(false)

func TestMain(m *testing.M) {
	log.MainTest(m)
}
