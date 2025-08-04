//go:build constantTime

package suites

import (
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/pairing/bls12381/circl"
)

func init() {
	register(circl.NewSuiteBLS12381())
	// This is a constant time implementation that should be
	// used as much as possible
	register(edwards25519.NewBlakeSHA256Ed25519())
}
