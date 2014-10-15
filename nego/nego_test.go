package nego

import (
	"fmt"
	"testing"
	"github.com/dedis/crypto"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/edwards"
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
			edwards.NewAES128SHA256Ed25519(true),
		}

	fakery := 10
	nentries := 10
	datalen := 16

	suites := make([]crypto.Suite, 0)
	for i := range(realSuites) {
		real := realSuites[i]
		for j := 0; j < fakery; j++ {
			suites = append(suites, &fakeSuite{real, j})
		}
	}

	nlevels := 5
	suiteLevel := make(map[crypto.Suite]int)
	entries := make([]Entry, 0)
	for i := range(suites) {
		suiteLevel[suites[i]] = nlevels
		nlevels++			// vary it a bit for testing

		// Create some entrypoints with this suite
		s := suites[i]
		for j := 0; j < nentries; j++ {
			pri := s.Secret().Pick(random.Stream)
			pub := s.Point().Mul(nil, pri)
			data := make([]byte, datalen)
			entries = append(entries, Entry{s,pub,data})
		}
	}

	w := Writer{}
	_,err := w.Layout(suiteLevel, entries, nil)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
}

