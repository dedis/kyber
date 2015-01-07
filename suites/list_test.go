package suites

import (
	"testing"

	"github.com/dedis/crypto/test"
)

func TestSuites(t *testing.T) {
	s := All()
	for name, suite := range s {
		println("Suite", name)
		test.TestSuite(suite)
	}
}
