package network

import (
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group"
	"github.com/dedis/onet/log"
)

var tSuite kyber.Group

func init() {
	tSuite, _ = group.Suite("Ed25519")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}
