package anon

import (
	"hash"

	"gopkg.in/dedis/kyber.v1"
)

type Suite interface {
	kyber.Group
	Cipher(key []byte, options ...interface{}) kyber.Cipher
	kyber.Encoding
	Hash() hash.Hash
}
