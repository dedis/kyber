package anon

import (
	"hash"

	"github.com/dedis/crypto"
)

// NOTE: here again a full Suite definition...
type Suite interface {
	crypto.Group
	Cipher(key []byte, options ...interface{}) crypto.Cipher
	crypto.Encoding
	Hash() hash.Hash
}
