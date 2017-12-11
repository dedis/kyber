package network

import (
	"testing"

	_ "github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/suites"
	"github.com/dedis/onet/log"
)

var tSuite = suites.MustFind("Ed25519")

func TestMain(m *testing.M) {
	log.MainTest(m)
}
