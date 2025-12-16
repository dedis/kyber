//go:build constantTime

package suites

import (
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

func init() {
	// This is a constant time implementation that should be
	// used as much as possible
	register(edwards25519.NewBlakeSHA256Ed25519())
}
