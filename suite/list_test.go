package suite

import (
	"github.com/dedis/crypto/test"
	"golang.org/x/net/context"
	"testing"
)

func TestSuites(t *testing.T) {
	s := All()
	for name, config := range s {
		println("Suite", name)
		test.TestSuite(config(context.Background()))
	}
}
