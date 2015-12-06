package sig

import (
	"crypto/cipher"
	"github.com/dedis/crypto/marshal"
	"golang.org/x/net/context"
	"hash"
)

// PublicKey is the abstract interface for a public signing key
// that can be used for signature verification.
// This interface may be used with a variety of signing schemes,
// but it assumes that the signing scheme produces and consumes
// fixed-size signatures.
type PublicKey interface {
	marshal.Marshaling

	// Produce a human-readable representation of a PublicKey
	//String() string

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
	Pick(rand cipher.Stream) SecretKey

	// Sign a hashed message, appending the signature to sig.
	// May further update the hash in the process of signing.
	Sign(sig []byte, hash hash.Hash, rand cipher.Stream) ([]byte, error)

	// Return the PublicKey for this SecretKey.
	PublicKey() PublicKey
}

// Scheme is an interface defining an abstract digital signature scheme.
// An instance provides constructors for PublicKey and SecretKey objects
// for a particular digital signature scheme.
type Scheme interface {
	Context() context.Context
	PublicKey() PublicKey
	SecretKey() SecretKey
}
