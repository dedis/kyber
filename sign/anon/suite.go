package anon

import (
	"hash"

	"github.com/dedis/crypto"
)

type Suite interface {
	crypto.Group
	Cipher(key []byte, options ...interface{}) crypto.Cipher
	crypto.Encoding
	Hash() hash.Hash
}
