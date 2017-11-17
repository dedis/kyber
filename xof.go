package kyber

import (
	"crypto/cipher"
)

// Sponge is an interface representing a primitive sponge function.
type Sponge interface {
	// XOR src data into sponge's internal state,
	// transform its state, and copy resulting state into dst.
	// Buffers must be either Rate or Rate+Capacity bytes long.
	Transform(dst, src []byte)

	// Return the number of data bytes the sponge can aborb in one block.
	Rate() int

	// Return the sponge's secret state capacity in bytes.
	Capacity() int

	// Clone clones a Sponge.
	Clone() Sponge
}

// Xof is an interface for extendable output functions.
type Xof interface {
	// Absorb introduces state into the internal state of the Xof.
	// Use it to put in keying material, or to put in material to be
	// hashed. If key does not fill the internal state until Rate(),
	// it will be padded with zeros until it does. Absorb returns
	// itself so that chaining during creation is possible:
	//     x := xof.New("keccak").Absorb(seed)
	Absorb(key []byte) Xof

	// Extract fills dst with pseudo-random numbers based
	// on the current internal state of the Xof. Use it as
	// a source of randomness, as a key stream to be XORed with
	// cleartext, or as a hash of all of the data previously
	// send to absorb.
	//
	// TODO: Explain what the theoretical limit is on extraction.
	Extract(dst []byte)

	// An Xof can be used as a ciper.Stream. It uses Extract to
	// take same number of bytes from the key stream as the length
	// of src.
	cipher.Stream

	// Rate returns the rate of the underlying sponge.
	Rate() int

	// Clone clones the Xof.
	Clone() Xof
}
