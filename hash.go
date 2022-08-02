package kyber

import (
	"hash"
	"io"
)

// A HashFactory is an interface that can be mixed in to local suite definitions.
type HashFactory interface {
	Hash() hash.Hash
}

// HashablePoint is an interface implemented by n
type HashablePoint interface {
	Hash([]byte) Point
}

// a scalar can be created via a hash and this is the interface for using it
type HashableScalar interface {
	Hash(HashFactory, io.Reader) (Scalar, error)
}
