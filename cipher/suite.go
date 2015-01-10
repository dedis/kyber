package cipher

import (
	"io"
	"reflect"
	"crypto/cipher"
)

// Generic reflection-driven "universal constructor" interface,
// which determines how to create concrete objects 
// instantiating a given set of abstract interface types.
type Constructor interface {

	// Create a fresh object of a given (usually interface) type.
	New(t reflect.Type) interface{}
}

// Random represents a generic source of cryptographic random bytes,
// which may be either read "verbatim" or used as a stream cipher.
type Random interface {
	io.Reader		// Read [pseudo-]random bytes
	cipher.Stream		// XOR-encrypt using [pseudo-]random bytes
}

// Suite represents an abstract cryptographic suite.
type Suite interface {

	// Builds on the generic universal constructor interface:
	// must at minimum know how to instantiate the State interface,
	// but may know how to instantiate other interfaces as well.
	Constructor

	// Return the recommended byte-length of keys for full security.
	KeyLen() int

	// Return the recommended byte-length of hashes for full security.
	// This is usually 2*KeyLen() to account for birthday attacks.
	HashLen() int

	// Create a fresh cryptographic state object seeded with
	// a standard initial state depending on nothing but the ciphersuite
	// and, if non-nil, the provided seed object(s).
	Cipher(key ...interface{}) Cipher

	// Create a fresh cryptographic cipher seeded with
	// strong private randomness.
	Random() Cipher

	// Read cryptographic object state from an input byte-stream.
	// The destination object structure must already be constructed,
	// except for interface variables that Constructor can instantiate
	// (atomic cryptographic objects such as State, Secret, Point).
	// The source may be a Random stream, to initialize objects randomly.
	Read(r io.Reader, obj ...interface{}) error

	// Write cryptographic object state to an output byte-stream.
	Write(w io.Writer, obj ...interface{}) error

	// Securely erase the in-memory state of cryptographic objects.
	Erase(obj ...interface{})
}

