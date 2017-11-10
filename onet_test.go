package onet

import (
	"testing"

	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/onet/log"
)

var suite = edwards25519.NewAES128SHA256Ed25519()

// To avoid setting up testing-verbosity in all tests
func TestMain(m *testing.M) {

	log.MainTest(m)
}
