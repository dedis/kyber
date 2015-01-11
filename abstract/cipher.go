package abstract

import (
)

// Cipher defines an interface to an abstract symmetric message cipher.
// The cipher embodies a secret that may be used to encrypt/decrypt data
// as well as to generate cryptographically random bits.
// The Cipher's state cryptographically absorbs all data that it processes,
// producing updated state usable to generate hashes and authenticators.
//
// The Encrypt and Decrypt methods process bytes through the Cipher.
// These methods each encrypt from a src byte-slice to a dst byte-slice.
// always processing exactly max(len(src),len(dst) bytes through the cipher.
// If src is shorter than dst, the missing src bytes are assumed to be zero.
// If dst is shorter than src, the extra output bytes are discarded.
// This means that Encrypt(dst, nil) may be used to produce pseudorandom bytes,
// and Encrypt(nil, src) may be used to absorb input without producing output.
// The cipher cryptographically pads or demarks calls in a cipher-specific way,
// so that a single call to Encrypt(dst, src) yields a different result
// from Encrypt(dst[:x], src[:x]) followed by Encrypt(dst[x:], src[x:])
//
// To form a keyed State from a generic unkeyed State,
// simply absorb the secret key via Encrypt(nil, key).
// The key may be any length, but the KeyLen method returns the optimal
// length for secret keys to achieve maximum security with this cipher.
//
// To compute a cryptographic hash, create an unkeyed State,
// then absorb the message via Encrypt(nil, message),
// and finally produce the digest via Encrypt(digest, nil).
// The digest may be any length, but the HashLen method returns the optimal
// length for hashes to achieve maximum security with this cipher.
// To compute a keyed cryptographic hash or message-authenticator,
// follow the same procedure but using a keyed State.
//
// For authenticated encryption, use Encrypt(ciphertext, plaintext)
// to encrypt the message while absorbing its content into the State,
// then use Encrypt(digest, nil) to produce the message authenticator.
// To decrypt and authenticate, call Decrypt(plaintext, ciphertext)
// followed by Encrypt(digest, nil) and check the resulting authenticator.
// The plaintext byte-slice may be shorter than the ciphertext slice,
// in which case the plaintext is securely padded with zeros on encryption
// and the ciphertext padding bytes are dropped on decryption;
// these padding bytes are still absorbed into the cipher state for security.
//
type Cipher interface {

	// Encrypt from src to dst and absorb the data into the cipher state,
	// and return the Cipher.
	Encrypt(dst, src []byte, options ...Option) Cipher

	// Decrypt from src to dst and absorb for authentication/MAC checking,
	// and return the Cipher.
	Decrypt(dst, src []byte, options ...Option) Cipher

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
}


// Option is a generic interface representing an option
// that may be passed to functions/methods that take a varying,
// extensible list of optional arguments, such as Cipher.Encrypt/Decrypt.
//
type Option interface {

	// Convert the option to a String for debugging, pretty-printing
	String() string
}


// If the More option is provided to Encrypt or Decrypt,
// the encryption src and dst must be a multiple of BlockSize,
// and the cipher does *not* pad or demark the end of the current message.
// Without the More argument, src and dst may be any length,
// and the cipher pads or demarks the end of the message in the usual way,
// accounting for partial messages processed in preceding calls with more set.
//
var More Option = moreOption{}

type moreOption struct {}

func (_ moreOption) String() string { return "More" }

