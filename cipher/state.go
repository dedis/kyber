package cipher

import (
)

// State represents an abstract interface to a symmetric message cipher.
// The state embodies a secret that may be used to encrypt/decrypt data
// as well as to generate cryptographically random bits.
// The cipher state cryptographically absorbs all data that it processes,
// producing updated state usable to generate hashes and authenticators.
//
// The Encrypt and Decrypt methods process bytes through the cipher.
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
type State interface {

	// Encrypt from src to dst and absorb the data into the cipher state.
	Encrypt(dst, src []byte)

	// Decrypt from src to dst and absorb for authentication/MAC checking.
	Decrypt(dst, src []byte)

	// Return the recommended byte-length of keys for full security.
	KeyLen() int

	// Return the recommended byte-length of hashes for full security.
	// This is usually 2*KeyLen() to account for birthday attacks.
	HashLen() int

	// Create a clone of this cryptographic state object,
	Clone() State
}

// BlockState provides optional block-based encryption and decryption,
// enabling the client to process large messages incrementally in blocks.
// BlockEncrypt and BlockDecrypt operate like Encrypt and Decrypt,
// but the provided arguments may represent partial-message buffers.
// If the more argument is true, src and dst must be a multiple of BlockSize,
// and the cipher does *not* pad or demark the end of the current message.
// If the more argument is false, src and dst may be any length,
// and the cipher pads or demarks the end of the message in the usual way,
// accounting for partial messages processed in preceding calls with more set.
//
type BlockState interface {

	// Encrypt blocks from src to dst and absorb into the cipher state.
	BlockEncrypt(dst, src []byte, more bool)

	// Decrypt blocks from src to dst and absorb into the cipher state.
	BlockDecrypt(dst, src []byte, more bool)

	// Return the block length required by this cipher.
	BlockSize() int
}

