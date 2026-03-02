//go:build !constantTime

package ecies

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/group/edwards25519vartime"
	"go.dedis.ch/kyber/v4/group/p256"
)

var suites = []struct {
	kyber.Group
}{
	{edwards25519.NewBlakeSHA256Ed25519()},
	{edwards25519vartime.NewBlakeSHA256Ed25519(false)},
	{edwards25519vartime.NewBlakeSHA256Ed25519(true)},
	{p256.NewBlakeSHA256P256()},
	{p256.NewBlakeSHA256QR512()},
}
