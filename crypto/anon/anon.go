// Package anon implements cryptographic primitives for anonymous communication.
package anon

import (
	"dissent/crypto"
)

// An anon.Set represents an explicit anonymity set
// as a list of public keys.
type Set []crypto.Point

