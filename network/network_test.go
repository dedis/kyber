package network

import (
	"testing"

	"github.com/dedis/onet/log"
)

var tSuite = DefaultSuite()

func TestMain(m *testing.M) {
	log.MainTest(m)
}
