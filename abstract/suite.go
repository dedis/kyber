package abstract

import (
	"crypto/cipher"
	"hash"
)

// Suite is an abstract interface to a full suite of
// public-key and symmetric-key crypto primitives
// chosen to be suited to each other and haver matching security parameters.
// A ciphersuite in this framework basically consists of three components:
// a hash function, a stream cipher, and an abstract group
// for public-key crypto.
//
// This interface adopts hashes and stream ciphers as its
// fundamental symmetric-key crypto abstractions because
// they are conceptually simple and directly complementary in function:
// a hash takes any desired number of input bytes
// and produces a small fixed number of output bytes,
// whereas a stream cipher takes a small fixed number of input bytes
// and produces any desired number of output bytes.
// While stream ciphers can be and often are constructed from block ciphers,
// we treat block ciphers as an implementation detail
// hidden below the abstraction level of this ciphersuite interface.
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

	// NewKey returns a freshly generated private key from the cipher stream.
	// If cipher == nil, it uses random.Stream.
	NewKey(cipher.Stream) Scalar
}

// Sum uses a given ciphersuite's hash function to checksum a byte-slice.
func Sum(suite Suite, data ...[]byte) []byte {
	h := suite.Hash()
	for _, b := range data {
		h.Write(b)
	}
	return h.Sum(nil)
}
