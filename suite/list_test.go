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

func TestNamed(t *testing.T) {
	_, err := Named("unknown")
	if err == nil {
		t.Fatal("Shouldn't find suite 'unknown'")
	}
	/* not sure what positive text makes sense for function-pointer Config
	s := All()
	for n := range s {
		search, _ := Named(n)
		if search != All()[n] {
			t.Fatal("Suite", n, "returned", search.String())
		}
	}
	*/
}
