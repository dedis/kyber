package suites

import (
	"gopkg.in/dedis/kyber.v2/group/edwards25519"
)

func init() {
	register(edwards25519.NewBlakeSHA256Ed25519())
}
