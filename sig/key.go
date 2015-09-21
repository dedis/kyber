package sig

import (
	"github.com/dedis/crypto/abstract"
	"hash"
)

// PublicKey is the abstract interface for a public signing key
// that can be used for signature verification.
// This interface may be used with a variety of signing schemes,
// but it assumes that the signing scheme produces and consumes
// fixed-size signatures.
type PublicKey interface {
	abstract.Marshaling

	// Produce a human-readable representation of a PublicKey
	String() string

	// Create an instance of the hash function this signature scheme uses.
	Hash() hash.Hash

	// Return the length in bytes of signatures generated via this scheme.
	SigSize() int

	// Verify a signature against a hashed message.
	// May further update the hash in the process of verifying.
	Verify(sig []byte, hash hash.Hash) error
}

// SecretKey is the abstract interface for a secret signing key
// that can be used for both signing and verification.
// This interface may be used with a variety of signing schemes,
// but it assumes that the signing scheme produces and consumes
// fixed-size signatures.
type SecretKey interface {
	PublicKey

	// Set to a fresh, randomly-chosen secret key and return self.
	Pick() SecretKey

	// Sign a hashed message, appending the signature to sig.
	// May further update the hash in the process of signing.
	Sign(sig []byte, hash hash.Hash) ([]byte, error)

	// Return the PublicKey for this SecretKey.
	PublicKey() PublicKey
}
