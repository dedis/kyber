package abstract

// Function is an interface representing a primitive sponge function.
type Sponge interface {

	// XOR src data into sponge's R bits and idx into its C bits,
	// transform its state, and copy resulting R bits into dst.
	// Buffers may overlap and may be short or nil.
	Transform(dst,src,idx []byte)

	// Return the number of data bytes the sponge can aborb in one block.
	Rate() int

	// Return the sponge's secret state capacity in bytes.
	Capacity() int

	// Create a copy of this Sponge with identical state
	Clone() Sponge
}

