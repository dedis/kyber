package cipher

import (
	"github.com/dedis/crypto/util"
)

// CipherHash wraps a generic mesage cipher to produce a Hash.
type CipherHash struct {
	orig, cur	State
	size   int
}

// interface representing an optional BlockSize method a Cipher may support
// if it is based on a block-based (or sponge function) cipher.
type cipherBlockSize interface {
	BlockSize() int
}

// Create a new Hash function generically from a message cipher instance,
// producing hashes whose length corresponds to the cipher's HashSize.
func NewCipherHash(state State) *CipherHash {
	return new(CipherHash).Init(state)
}

// Initialize a CipherHash with a given message cipher instance,
// producing hashes whose length corresponds to the cipher's HashSize.
func (ch *CipherHash) Init(state State) *CipherHash {
	*ch = CipherHash{state, state.Clone(), state.HashSize()}
	return ch
}

// Absorb bytes into the CipherHash, satisfying the io.Writer interface.
func (ch *CipherHash) Write(src []byte) (int, error) {
	ch.cur.Partial(nil, nil, src)
	return len(src), nil
}

// Compute the checksum of the bytes absorbed so far,
// appending the hash onto buf and returning the resulting slice.
func (ch *CipherHash) Sum(buf []byte) []byte {

	// Clone the Cipher to leave the original's state unaffected
	c := ch.cur.Clone()
	c.Message(nil, nil, nil) // finalize the message

	// Squeeze out a hash of any requested size.
	buf, hash := util.Grow(buf, ch.size)
	c.Partial(hash, nil, nil)
	return buf
}

// Reset the CipherHash to its initial state.
func (ch *CipherHash) Reset() {
	ch.cur = ch.orig.Clone()
}

// Return the size in bytes of hashes this CipherHash produces.
func (ch *CipherHash) Size() int {
	return ch.size
}

// Set the size of hashes this CipherHash will produce
// in subsequent calls to Sum,
// overriding the default determined by the underlying cipher.
func (ch *CipherHash) SetSize(size int) *CipherHash {
	if size <= 0 {
		panic("invalid hash size")
	}
	ch.size = size
	return ch
}

// Return the recommended block size for maximum performance,
// or 1 if no block size information is available.
func (ch *CipherHash) BlockSize() int {
	bs, ok := ch.cur.(cipherBlockSize)
	if !ok {
		return 1 // default for non-block-based ciphers
	}
	return bs.BlockSize()
}
