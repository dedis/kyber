// Package anon implements cryptographic primitives for anonymous communication.
package anon

import (
	"go.dedis.ch/kyber/v4"
)

// Set represents an explicit anonymity set
// as a list of public keys.
type Set []kyber.Point
