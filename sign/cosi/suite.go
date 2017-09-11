package cosi

import (
	"crypto/sha512"
	"hash"

	"github.com/dedis/kyber/group/edwards25519"
)

// Suite specifies a cipher suite using AES-128, SHA512, and the Edwards25519 curve.
type Suite struct {
	*edwards25519.SuiteEd25519
}

// Hash returns an instance of the SHA512 hash function.
func (s *Suite) Hash() hash.Hash {
	return sha512.New()
}
