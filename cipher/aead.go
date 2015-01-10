package cipher

import (
	"errors"
	"crypto/cipher"
	"crypto/subtle"
	"github.com/dedis/crypto/util"
)

type cipherAEAD struct {
	Cipher
}

// Wrap an abstract stateful cipher to implement
// the Authenticated Encryption with Associated Data (AEAD) interface.
func NewAEAD(c Cipher) cipher.AEAD {
	return &cipherAEAD{c}
}

func (ca *cipherAEAD) NonceSize() int {
	return ca.KeySize()
}

func (ca *cipherAEAD) Overhead() int {
	return ca.KeySize()
}

func (ca *cipherAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {

	// Fork off a temporary Cipher state indexed via the nonce
	ct := ca.Clone(nonce)

	// Encrypt the plaintext and update the temporary Cipher state
	dst,ciphertext := util.Grow(dst, len(plaintext))
	ct.Encrypt(ciphertext, plaintext)

	// Compute and append the authenticator based on post-encryption state
	dst,auth := util.Grow(dst, ct.KeySize())
	ct.Encrypt(auth, nil)

	return dst
}

func (ca *cipherAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {

	// Fork off a temporary Cipher state indexed via the nonce
	ct := ca.Clone(nonce)

	// Compute the plaintext's length
	authl := ct.KeySize()
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

