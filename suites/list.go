// This package contains lists of ciphersuites
// defined elsewhere in other packages.
package suites

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/crypto/nist"
)

// Suites represents a map from ciphersuite name to ciphersuite.
type Suites map[string]abstract.Suite

func (s Suites) add(suite abstract.Suite) {
	s[suite.String()] = suite
}

func All() Suites {
	s := make(Suites)
	s.add(nist.NewAES128SHA256P256())
	s.add(ed25519.NewAES128SHA256Ed25519(false))
	return s
}

// XXX add Stable() and Experimental() sub-lists?
