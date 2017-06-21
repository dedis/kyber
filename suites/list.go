// This package contains lists of ciphersuites
// defined elsewhere in other packages.
package suites

import (
	"fmt"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/ed25519"
	"github.com/dedis/kyber/edwards"
	"github.com/dedis/kyber/nist"
)

// Suites represents a map from ciphersuite name to ciphersuite.
type Suites map[string]abstract.Suite

// All Returns a map of all suites
func All() Suites {
	s := make(Suites)
	s.add(nist.NewAES128SHA256P256())
	s.add(nist.NewAES128SHA256QR512())
	s.add(ed25519.NewAES128SHA256Ed25519(false))
	s.add(edwards.NewAES128SHA256Ed25519(false))
	return s
}

// StringToSuite returns the suite for a string, or an error.
func StringToSuite(s string) (abstract.Suite, error) {
	suite, ok := All()[s]
	if !ok {
		return nil, fmt.Errorf("Didn't find suite %s", s)
	}
	return suite, nil
}

func (s Suites) add(suite abstract.Suite) {
	s[suite.String()] = suite
}

// XXX add Stable() and Experimental() sub-lists?
