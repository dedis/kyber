// Package anon implements cryptographic primitives for anonymous communication.
package anon

import (
	"gopkg.in/dedis/crypto.v0/abstract"
)

// An anon.Set represents an explicit anonymity set
// as a list of public keys.
type Set []abstract.Point

// A private key representing a member of an anonymity set
type PriKey struct {
	Set                  // Public key-set
	Mine int             // Index of the public key I own
	Pri  abstract.Scalar // Private key for that public key
}

// XXX name PubSet, PriSet?
