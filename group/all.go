// Package group holds a reference to all kyber.Group and to all
// cipher suites defined. It provides access to suites by name,
// case-insensitively.
//
// Currently, only the "ed25519" suite is available by default. To
// have access to the "curve25519" and all nist/ suites, one needs to
// build the kyber library with the tag "vartime", such as:
//
//   go build -tags vartime
package group

import (
	"errors"
	"strings"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
)

var suites = map[string]kyber.Group{}

func register(g kyber.Group) {
	suites[strings.ToLower(g.String())] = g
}

func init() {
	register(edwards25519.NewBlakeSHA256Ed25519())
}

// ErrUnknownSuite indicates that the suite was not one of the
// registered suites.
var ErrUnknownSuite = errors.New("unknown suite")

// Suite looks up a suite by name.
func Suite(name string) (kyber.Group, error) {
	if s, ok := suites[strings.ToLower(name)]; ok {
		return s, nil
	}
	return nil, ErrUnknownSuite
}

// MustSuite looks up a suite by name and panics if it is not found.
func MustSuite(name string) kyber.Group {
	s, err := Suite(name)
	if err != nil {
		panic("Suite " + name + " not found.")
	}
	return s
}
