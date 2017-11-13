// Package group holds a reference to all kyber.Group and to all cipher suites
// defined. It provides a quick access to one specific suite using the
//
//  Suite("ed25519")
//
// method. Currently, only the "ed25519" suite is available by default. To have
// access to the "curve25519" and all nist/ suites, one needs to build the
// kyber library with the tag "vartime", such as:
//
//   go build -tags vartime
//
// Note that all suite and groups references are case insensitive.
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
	register(edwards25519.NewAES128SHA256Ed25519())
}

var ErrUnknownSuite = errors.New("unknown suite")

// Suite return
func Suite(name string) (kyber.Group, error) {
	if s, ok := suites[strings.ToLower(name)]; ok {
		return s, nil
	}
	return nil, ErrUnknownSuite
}
