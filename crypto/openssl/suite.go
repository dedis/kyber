package openssl

import (
	"hash"
	"crypto/cipher"
	"dissent/crypto"
)


type OpenSSL struct {
	curve
} 


func (s *OpenSSL) HashLen() int {
	return 32	// SHA256_DIGEST_LENGTH
}

func (s *OpenSSL) Hash() hash.Hash {
	return newSha256()
}

func (s *OpenSSL) KeyLen() int {
	return 16	// AES128
}

func (s *OpenSSL) Stream(key []byte) cipher.Stream {
	if len(key) != 16 {
		panic("wrong AES key size")
	}
	return newAesCtr(key)
}

func NewOpenSSL() *OpenSSL {
	s := new(OpenSSL)
	s.curve.InitP256()
	return s
}

func TestOpenSSL() {
	println("\nTestOpenSSL()\n")

	suite := NewOpenSSL()
	crypto.TestSuite(suite)
}


