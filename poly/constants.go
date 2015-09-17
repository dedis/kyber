package poly

import (
	"github.com/dedis/crypto/edwards"
)

const (
	MINIMUM = iota
	MODERATE
	MAXIMUM
)

var SECURITY int = MAXIMUM

var SUITE = edwards.NewAES128SHA256Ed25519(true)
