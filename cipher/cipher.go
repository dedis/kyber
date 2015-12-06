package cipher

import (
	"crypto/cipher"
	"hash"
)

type Hash hash.Hash
type Stream cipher.Stream
type Block cipher.Block
