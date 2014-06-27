// Package openssl implements a ciphersuite
// based on OpenSSL's crypto library.
package openssl

import (
	"hash"
	"crypto/cipher"
	"dissent/crypto"
)


type openSSL struct {
	curve
} 


func (s *openSSL) HashLen() int {
	return 32	// SHA256_DIGEST_LENGTH
}

func (s *openSSL) Hash() hash.Hash {
	return newSha256()
}

func (s *openSSL) KeyLen() int {
	return 16	// AES128
}

func (s *openSSL) Stream(key []byte) cipher.Stream {
	if len(key) != 16 {
		panic("wrong AES key size")
	}
	return newAesCtr(key)
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES128SHA256P256() crypto.Suite {
	s := new(openSSL)
	s.curve.InitP256()
	return s
}

