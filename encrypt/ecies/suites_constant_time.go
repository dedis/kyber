//go:build constantTime

package ecies

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

var suites = []struct {
	kyber.Group
}{
	{edwards25519.NewBlakeSHA256Ed25519()},
}
