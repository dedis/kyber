// Package aes implements the general Cipher interface
// using AES, SHA2, and HMAC.
package aes

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

// NewBlockCipher creates a conventional AES block cipher.
func NewBlockCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// NewCipher128 creates an abstract.Cipher based on the AES-128 block cipher
// and the SHA2-256 hash algorithm.
func NewCipher128() abstract.Cipher {
	return cipher.NewBlockCipher(aes.NewCipher, sha256.New,
		aes.BlockSize, 128/8, 256/8)
}

// NewCipher192 creates an abstract.Cipher based on the AES-192 block cipher
// and the SHA2-384 hash algorithm.
func NewCipher192() abstract.Cipher {
	return cipher.NewBlockCipher(aes.NewCipher, sha512.New384,
		aes.BlockSize, 192/8, 384/8)
}

// NewCipher256 creates an abstract.Cipher based on the AES-256 block cipher
// and the SHA2-512 hash algorithm.
func NewCipher256() abstract.Cipher {
	return cipher.NewBlockCipher(aes.NewCipher, sha512.New,
		aes.BlockSize, 256/8, 512/8)
}
