// Package anon implements cryptographic primitives for anonymous communication.
package anon

import (
	"gopkg.in/dedis/kyber.v2"
)

// Set represents an explicit anonymity set
// as a list of public keys.
type Set []kyber.Point
