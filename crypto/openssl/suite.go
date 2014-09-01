// Package openssl implements a ciphersuite
// based on OpenSSL's crypto library.
package openssl

import (
	"hash"
	"crypto/cipher"
	"dissent/crypto"
)


type suite128 struct {
	curve
} 

func (s *suite128) HashLen() int {
	return 32	// SHA256_DIGEST_LENGTH
}

func (s *suite128) Hash() hash.Hash {
	return NewSHA256()
}

func (s *suite128) KeyLen() int {
	return 16	// AES128
}

func (s *suite128) Stream(key []byte) cipher.Stream {
	if len(key) != 16 {
		panic("wrong AES key size")
	}
	return crypto.BlockStream(NewAES(key), nil)
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES128SHA256P256() crypto.Suite {
	s := new(suite128)
	s.curve.InitP256()
	return s
}



type suite192 struct {
	curve
} 

func (s *suite192) HashLen() int {
	return 48	// SHA384_DIGEST_LENGTH
}

func (s *suite192) Hash() hash.Hash {
	return NewSHA384()
}

func (s *suite192) KeyLen() int {
	return 24	// AES192
}

func (s *suite192) Stream(key []byte) cipher.Stream {
	if len(key) != 24 {
		panic("wrong AES key size")
	}
	return crypto.BlockStream(NewAES(key), nil)
}


// Ciphersuite based on AES-192, SHA-384, and the NIST P-384 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES192SHA384P384() crypto.Suite {
	s := new(suite192)
	s.curve.InitP384()
	return s
}



type suite256 struct {
	curve
} 

func (s *suite256) HashLen() int {
	return 64	// SHA512_DIGEST_LENGTH
}

func (s *suite256) Hash() hash.Hash {
	return NewSHA512()
}

func (s *suite256) KeyLen() int {
	return 32	// AES256
}

func (s *suite256) Stream(key []byte) cipher.Stream {
	if len(key) != 32 {
		panic("wrong AES key size")
	}
	return crypto.BlockStream(NewAES(key), nil)
}


// Ciphersuite based on AES-256, SHA-512, and the NIST P-521 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES256SHA512P521() crypto.Suite {
	s := new(suite256)
	s.curve.InitP521()
	return s
}

