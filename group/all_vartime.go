// +build vartime

package group

import (
	"github.com/dedis/kyber/group/curve25519"
	"github.com/dedis/kyber/group/nist"
)

func init() {
	register(curve25519.NewAES128SHA256Ed25519(false))
	register(curve25519.NewAES128SHA256Ed25519(true))
	register(nist.NewAES128SHA256P256())
	register(nist.NewAES128SHA256QR512())
}
