package share

import "go.dedis.ch/kyber/v4"

// Suite defines the capabilities required by the share package.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}
