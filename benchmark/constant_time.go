//go:build constantTime

package main

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/pairing/bls12381/circl"
)

// Define variables to use in constant-time benchmark
var (
	newSignatureSuite = circl.NewSuite
	suites            = []kyber.Group{
		edwards25519.NewBlakeSHA256Ed25519(),
		circl.NewSuiteBLS12381(),
	}
)
