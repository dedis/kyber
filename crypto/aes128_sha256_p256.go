package crypto

import (
	"hash"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

type AES128SHA256P256 struct {
	P256
} 

// SHA256 hash function
func (s AES128SHA256P256) HashLen() int { return sha256.Size }
func (s AES128SHA256P256) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s AES128SHA256P256) KeyLen() int { return 16 }
func (s AES128SHA256P256) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

func NewAES128SHA256P256() *AES128SHA256P256 {
	suite := new(AES128SHA256P256)
	suite.P256.Init()
	return suite
}

