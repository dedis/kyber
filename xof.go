package kyber

import (
	"crypto/cipher"
	"hash"
	"io"
)

// An XOF is an extendable output function, which is a cryptographic
// primitive that can take arbitrary input like a hash, and then create
// a stream of output, up to a limit determined by the size of the internal
// state of the XOF.
type XOF interface {
	// Write absorbs more data into the hash's state. It panics if called
	// after Read. Use Reseed() to
	io.Writer

	// Read reads more output from the hash. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	// An XOF implements cipher.Stream, so that callers can use XORKeyStream
	// to encrypt/decrypt data. The key stream is read from the XOF using
	// the io.Reader interface.
	cipher.Stream

	// KeySize is the number of bytes that must be written to the XOF before
	// it is ready to give secure output.
	KeySize() int

	// Reseed makes an XOF writeable again after it has been read from.
	Reseed()

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF
}

// An XOFFactory is an interface that can be mixed in to local suite definitions.
type XOFFactory interface {
	// XOF creates a new XOF, feeding seed to it via it's Write method. If seed
	// is nil or []byte{}, the XOF is unseeded and will always produce the same
	// bytes from Read.
	XOF(seed []byte) XOF
}

type HashFactory interface {
	Hash() hash.Hash
}
