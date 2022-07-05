package kyber

import (
	"hash"
)

// A HashFactory is an interface that can be mixed in to local suite definitions.
type HashFactory interface {
	Hash() hash.Hash
}

// HashablePoint is an interface implemented by n
type HashablePoint interface {
	Hash([]byte) Point
}
