package nego

import (
	"fmt"
	"testing"
	"dissent/crypto"
	"dissent/crypto/openssl"
)

// Simple harness to create lots of fake ciphersuites out of a few real ones,
// for testing purposes.
type fakeSuite struct {
	crypto.Suite
	idx int
}

func (f *fakeSuite) String() string {
	return fmt.Sprintf("%s(%d)", f.Suite.String(), f.idx)
}


func TestNego(t *testing.T) {

	realSuites := []crypto.Suite{
			openssl.NewAES128SHA256P256(),
			openssl.NewAES192SHA384P384(),
			openssl.NewAES256SHA512P521(),
		}

	fakery := 10
	suites := make([]crypto.Suite, 0)
	for i := range(realSuites) {
		real := realSuites[i]
		for j := 0; j < fakery; j++ {
			suites = append(suites, &fakeSuite{real, j})
		}
	}

	nlevels := 5
	suiteLevel := make(map[crypto.Suite]int)
	for i := range(suites) {
		suiteLevel[suites[i]] = nlevels
		nlevels++			// vary it a bit for testing
	}

	w := Writer{}
	_,err := w.Init(suiteLevel, 0, nil, nil)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
}

