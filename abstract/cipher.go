package abstract

import (
	"errors"
	"crypto/cipher"
	"crypto/subtle"
	"github.com/dedis/crypto/util"
)

// Cipher represents an abstract stateful symmetric cipher,
// which implements authenticated encryption of variable-length messages,
// and can also function as a hash and a stream cipher.
// This interface is very experimental and will certainly change,
// and may go away entirely.
type Cipher interface {

	// Encrypt bytes from src to dst, updating the sponge state.
	// If dst == nil, absorbs input without producing output.
	// If src == nil, squeezes output based on an input of zero bytes.
	// Returns the number of bytes encrypted.
	Encrypt(dst,src []byte) int

	// Decrypt bytes from src to dst, updating the sponge state.
	// Returns the number of bytes decrypted, or an error on failure.
	Decrypt(dst,src []byte) int

	// Create a copy of this SpongeCipher with identical state,
	// except indexed via the variable-length bytes in idx.
	Clone(idx []byte) Cipher

	// Return the recommended size of key inputs for full security.
	// Hashes should be length 2*KeyLen() due to birthday attacks.
	KeyLen() int
}


type cipherAEAD struct {
	Cipher
}

// Wrap an abstract stateful cipher to implement
// the Authenticated Encryption with Associated Data (AEAD) interface.
func CipherAEAD(c Cipher) cipher.AEAD {
	return &cipherAEAD{c}
}

func (ca *cipherAEAD) NonceSize() int {
	return ca.KeyLen()
}

func (ca *cipherAEAD) Overhead() int {
	return ca.KeyLen()
}

func (ca *cipherAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {

	// Fork off a temporary Cipher state indexed via the nonce
	ct := ca.Clone(nonce)

	// Encrypt the plaintext and update the temporary Cipher state
	dst,ciphertext := util.Grow(dst, len(plaintext))
	ct.Encrypt(ciphertext, plaintext)

	// Compute and append the authenticator based on post-encryption state
	dst,auth := util.Grow(dst, ct.KeyLen())
	ct.Encrypt(auth, nil)

	return dst
}

func (ca *cipherAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {

	// Fork off a temporary Cipher state indexed via the nonce
	ct := ca.Clone(nonce)

	// Compute the plaintext's length
	authl := ct.KeyLen()
	plainl := len(ciphertext) - authl
	if plainl < 0 {
		return nil,errors.New("AEAD ciphertext too short")
	}

	// Decrypt the plaintext and update the temporary Cipher state
	dst,plaintext := util.Grow(dst, plainl)
	ct.Decrypt(plaintext, ciphertext[:plainl])

	// Compute and check the authenticator based on post-encryption state
	auth := make([]byte, authl)
	ct.Encrypt(auth, nil)
	if subtle.ConstantTimeCompare(auth, ciphertext[plainl:]) == 0 {
		return nil,errors.New("AEAD authenticator check failed")
	}

	return dst,nil
}

