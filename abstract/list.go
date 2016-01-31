// This package contains lists of ciphersuites
// defined elsewhere in other packages.
package abstract

import (
	"fmt"
)

// Suites represents a map from ciphersuite name to ciphersuite.
type Suites map[string]Suite

var allSuites Suites

// Returns a map of all suites
func AllSuites() Suites {
	if allSuites == nil {
		allSuites = make(map[string]Suite, 0)
	}
	return allSuites
}

// StrintToSuite returns the suite for a string, or an error.
func StringToSuite(s string) (Suite, error) {
	suite, ok := allSuites[s]
	if !ok {
		return nil, fmt.Errorf("Didn't find suite %s", s)
	}
	return suite, nil
}

func AddSuite(suite Suite) {
	_, exists := AllSuites()[suite.String()]
	if !exists {
		allSuites[suite.String()] = suite
	}
}

// XXX add Stable() and Experimental() sub-lists?
