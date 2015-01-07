package suites

import (
	"github.com/dedis/crypto/test"
	"testing"
)

func TestSuites(t *testing.T) {
	s := All()
	for name, suite := range s {
		println("Suite", name)
		test.TestSuite(suite)
	}
}
