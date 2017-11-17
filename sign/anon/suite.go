package anon

import (
	"github.com/dedis/kyber"
)

// Suite represents the set of functionalities needed by the package anon.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Encoding
}
