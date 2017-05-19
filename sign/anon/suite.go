package anon

import (
	"hash"

	"github.com/dedis/kyber"
)

type Suite interface {
	kyber.Group
	Cipher(key []byte, options ...interface{}) kyber.Cipher
	kyber.Encoding
	Hash() hash.Hash
}
