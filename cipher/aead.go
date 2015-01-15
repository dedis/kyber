package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/util"
)

type cipherAEAD struct {
	abstract.Cipher
}

// Wrap an abstract message Cipher to implement
// the Authenticated Encryption with Associated Data (AEAD) interface.
func NewAEAD(c abstract.Cipher) cipher.AEAD {
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
	ct := ca.Clone()
	ct.Crypt(nil, nonce)

	// Encrypt the plaintext and update the temporary Cipher state
	dst, ciphertext := util.Grow(dst, len(plaintext))
	ct.Crypt(ciphertext, plaintext, abstract.Encrypt)

	// Compute and append the authenticator based on post-encryption state
	dst, auth := util.Grow(dst, ct.KeySize())
	ct.Crypt(auth, nil, abstract.Encrypt)

	return dst
}

func (ca *cipherAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {

	// Fork off a temporary Cipher state indexed via the nonce
	ct := ca.Clone()
	ct.Crypt(nil, nonce)

	// Compute the plaintext's length
	authl := ct.KeySize()
	plainl := len(ciphertext) - authl
	if plainl < 0 {
		return nil, errors.New("AEAD ciphertext too short")
	}

	// Decrypt the plaintext and update the temporary Cipher state
	dst, plaintext := util.Grow(dst, plainl)
	ct.Crypt(plaintext, ciphertext[:plainl], abstract.Decrypt)

	// Compute and check the authenticator based on post-encryption state
	auth := make([]byte, authl)
	ct.Crypt(auth, nil, abstract.Decrypt)
	if subtle.ConstantTimeCompare(auth, ciphertext[plainl:]) == 0 {
		return nil, errors.New("AEAD authenticator check failed")
	}

	return dst, nil
}
