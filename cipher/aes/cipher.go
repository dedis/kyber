package aes

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

// NewCipher128 creates a Cipher based on the AES-128 block cipher
// and the SHA2-256 hash algorithm.
func NewCipher128() abstract.Cipher {
	return cipher.NewBlockCipher(aes.NewCipher, sha256.New,
					aes.BlockSize, 128/8, 256/8)
}

// NewCipher192 creates a Cipher based on the AES-192 block cipher
// and the SHA2-384 hash algorithm.
func NewCipher192() abstract.Cipher {
	return cipher.NewBlockCipher(aes.NewCipher, sha512.New384,
					aes.BlockSize, 192/8, 384/8)
}

// NewCipher256 creates a Cipher based on the AES-256 block cipher
// and the SHA2-512 hash algorithm.
func NewCipher256() abstract.Cipher {
	return cipher.NewBlockCipher(aes.NewCipher, sha512.New,
					aes.BlockSize, 256/8, 512/8)
}

