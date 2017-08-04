package onet

import (
	"testing"

	"gopkg.in/dedis/kyber.v1/group/edwards25519"
	"gopkg.in/dedis/onet.v2/log"
)

var suite = edwards25519.NewAES128SHA256Ed25519(false)

// To avoid setting up testing-verbosity in all tests
func TestMain(m *testing.M) {

	log.MainTest(m)
}
