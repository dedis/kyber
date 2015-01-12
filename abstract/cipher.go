package abstract

import (
	"io"
	"crypto/cipher"
)

// Cipher defines an interface to an abstract symmetric message cipher.
// The cipher embodies a secret that may be used to encrypt/decrypt data
// as well as to generate cryptographically random bits.
// The Cipher's state cryptographically absorbs all data that it processes,
// producing updated state usable to generate hashes and authenticators.
//
// The Crypt method encrypts or decrypts bytes through the Cipher,
// from a src byte-slice to a dst byte-slice.
// A call to Crypt always processes exactly max(len(src),len(dst) bytes.
// If src is shorter than dst, the missing src bytes are assumed to be zero.
// If dst is shorter than src, the extra output bytes are discarded.
// This means that Crypt(dst, nil) may be used to produce pseudorandom bytes,
// and Crypt(nil, src) may be used to absorb input without producing output.
// The cipher cryptographically pads or demarks calls in a cipher-specific way,
// so that a single call to Crypt(dst, src) yields a different result
// from Crypt(dst[:x], src[:x]) followed by Crypt(dst[x:], src[x:])
//
// Any Cipher has a configurable Direction, which may be
// OneWay, Encrypt, or Decrypt.
// OneWay is the default, suitable for hashing or generating random bytes.
// Encrypt and Decrypt provide a reversible transformation when needed.
// OneWay may be behaviorally equivalent to either Encrypt or Decrypt,
// depending on the specific Cipher.
//
// To form a keyed Cipher from a generic unkeyed Cipher,
// simply absorb the secret key via Crypt(nil, key).
// The key may be any length, but the KeyLen method returns the optimal
// length for secret keys to achieve maximum security with this cipher.
//
// To compute a cryptographic hash, create an unkeyed Cipher,
// then absorb the message via Crypt(nil, message),
// and finally produce the digest via Crypt(digest, nil).
// The digest may be any length, but the HashLen method returns the optimal
// length for hashes to achieve maximum security with this cipher.
// To compute a keyed cryptographic hash or message-authenticator,
// follow the same procedure but using a keyed Cipher.
//
// For authenticated encryption, use Crypt(ciphertext, plaintext, Encrypt)
// to encrypt the message while absorbing its content into the Cipher,
// then use Crypt(digest, nil, Encrypt) to produce the message authenticator.
// To decrypt and authenticate, call Crypt(plaintext, ciphertext, Decrypt)
// then Crypt(digest, nil, Decrypt) and check the resulting authenticator.
// The plaintext byte-slice may be shorter than the ciphertext slice,
// in which case the plaintext is securely padded with zeros on encryption
// and the ciphertext padding bytes are dropped on decryption;
// these padding bytes are still absorbed into the cipher state for security.
//
type Cipher interface {

	// Transform bytes from src to dst,
	// absorbing processed data into the cipher state,
	// and return the Cipher.
	Crypt(dst, src []byte, options ...interface{}) Cipher

	// Create a clone of this cryptographic state object,
	// optionally absorbing src into the clone's state.
	Clone(src []byte) Cipher

	// Return recommended size in bytes of secret keys for full security.
	KeySize() int

	// Return recommended size in bytes of hashes for full security.
	// This is usually 2*KeyLen() to account for birthday attacks.
	HashSize() int

	// Return the size of block in which this cipher processes data:
	// processing may be slightly more efficient in chunks this size.
	BlockSize() int

	// A Cipher also implements the standard Read and Write I/O methods.
	// Read(dst) is equivalent to Crypt(dst, nil, More{}).
	// Write(src) is equivalent to Crypt(nil, src, More{}).
	io.ReadWriter

	// Backwards-compatibility with the Stream cipher interface.
	// XXX this interface inclusion is provisional and may be dropped.
	cipher.Stream
}

// Direction selects between the Encrypt and Decrypt modes of a Cipher.
// When no Direction is specified to a Cipher, the default is OneWay,
// which produces cryptographic randomness that need not be reversible.
type Direction int

const (
	OneWay  Direction = 0  // one-way, no reversibility needed
	Encrypt Direction = 1  // encryption direction
	Decrypt Direction = -1 // decryption direction
)

// More is an option that may be provided to Cipher.Crypt
// to process a message incrementally.  With this option,
// the cipher does *not* pad or demark the end of the current message.
//
type More struct{}

// internal type for the simple options above
type option struct{ name string }

func (o *option) String() string { return o.name }


// Pass NoKey to a Cipher constructor to create an unkeyed Cipher.
var NoKey = []byte{}

// Pass RandomKey to a Cipher constructor to create a randomly seeded Cipher.
var RandomKey []byte = nil

