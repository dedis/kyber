package abstract_test

import (
	"github.com/dedis/crypto/abstract"
	_ "github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/test"
	"testing"
)

func TestSuites(t *testing.T) {
	s := abstract.AllSuites()
	for _, suite := range s {
		test.TestSuite(suite)
	}
}

func TestString(t *testing.T) {
	_, err := abstract.StringToSuite("unknown")
	if err == nil {
		t.Fatal("Shouldn't find suite 'unknown'")
	}
	s := abstract.AllSuites()
	for n, _ := range s {
		search, _ := abstract.StringToSuite(n)
		if n != search.String() {
			t.Fatal("Suite", n, "returned", search.String())
		}
	}
}
