package kyber

import (
	"hash"
)

// Suite is an kyber.interface to a full suite of
// public-key and symmetric-key crypto primitives
// chosen to be suited to each other and haver matching security parameters.
// A ciphersuite in this framework basically consists of three components:
// a hash function, a stream cipher, and an kyber.group
// for public-key kyber.
//
// This interface adopts hashes and stream ciphers as its
// fundamental symmetric-key crypto kyber.ons because
// they are conceptually simple and directly complementary in function:
// a hash takes any desired number of input bytes
// and produces a small fixed number of output bytes,
// whereas a stream cipher takes a small fixed number of input bytes
// and produces any desired number of output bytes.
// While stream ciphers can be and often are constructed from block ciphers,
// we treat block ciphers as an implementation detail
// hidden below the kyber.on level of this ciphersuite interface.
type Suite interface {

	// Create a cryptographic Cipher with a given key and configuration.
	// If key is nil, creates a Cipher seeded with a fresh random key.
	Cipher(key []byte, options ...interface{}) Cipher

	// Symmetric-key hash function
	Hash() hash.Hash

	// Abstract group for public-key crypto
	Group

	// Fixed-length binary encoding for all crypto objects
	Encoding

	// Generic constructor to instantiate any abstract interface type
	// supported by this suite: at least Cipher, Hash, Point, Scalar.
	Constructor
}

// Sum uses a given ciphersuite's hash function to checksum a byte-slice.
func Sum(suite Suite, data ...[]byte) []byte {
	h := suite.Hash()
	for _, b := range data {
		h.Write(b)
	}
	return h.Sum(nil)
}
