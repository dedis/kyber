// +build vartime

package suites

import (
	"gopkg.in/dedis/kyber.v2/group/curve25519"
	"gopkg.in/dedis/kyber.v2/group/nist"
)

func init() {
	register(curve25519.NewBlakeSHA256Curve25519(false))
	register(curve25519.NewBlakeSHA256Curve25519(true))
	register(nist.NewBlakeSHA256P256())
	register(nist.NewBlakeSHA256QR512())
}
