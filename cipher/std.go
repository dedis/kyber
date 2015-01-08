package cipher

import (
	"hash"
	"crypto/cipher"
)

// Aliases of some standard Go library cipher package types

type Stream cipher.Stream
type Block cipher.Block
type AEAD cipher.AEAD

// Standard Hash interface, used for cryptographic and conventional hashes.
type Hash hash.Hash

