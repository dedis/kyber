// Package anon implements cryptographic primitives for anonymous communication.
package anon

import (
	"github.com/dedis/crypto/abstract"
)

// An anon.Set represents an explicit anonymity set
// as a list of public keys.
type Set []abstract.Point

// A private key representing a member of an anonymity set
type PriKey struct {
<<<<<<< HEAD
	Set			// Public key-set
	Mine int		// Index of the public key I own
	Pri abstract.Scalar	// Private key for that public key
=======
	Set                  // Public key-set
	Mine int             // Index of the public key I own
	Pri  abstract.Secret // Private key for that public key
>>>>>>> development
}

// XXX name PubSet, PriSet?
