//go:build !constantTime

package main

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	nist "go.dedis.ch/kyber/v4/group/p256"
	"go.dedis.ch/kyber/v4/pairing/bls12381/circl"
	"go.dedis.ch/kyber/v4/pairing/bls12381/gnark"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/pairing/bn256"
)

// Define variables to use in variable-time benchmark
var (
	newSignatureSuite = bn256.NewSuite
	suites            = []kyber.Group{
		nist.NewBlakeSHA256P256(), nist.NewBlakeSHA256QR512(),
		bn256.NewSuiteG1(),
		bn254.NewSuiteG1(),
		edwards25519.NewBlakeSHA256Ed25519(),
		circl.NewSuiteBLS12381(),
		gnark.NewSuiteBLS12381(),
		kilic.NewSuiteBLS12381(),
	}
)
