package kyber

import (
	"crypto/cipher"
	"io"
)

// An XOF is an extendable output function, which is a cryptographic
// primitive that can take arbitrary input like a hash, and then create
// a stream of output, up to a limit determined by the size of the internal
// state of the XOF.
type XOF interface {
	// Write absorbs more data into the hash's state. It panics if called
	// after Read.
	io.Writer

	// Read reads more output from the hash. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	cipher.Stream

	Clone() XOF
	KeySize() int
}
