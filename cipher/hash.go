package cipher

import (
	"github.com/dedis/crypto/util"
)

// Wrapper to use a generic mesage cipher as a Hash
type cipherHash struct {
	cipher func(key []byte) State
	cur    State
	size   int
}

// interface representing an optional BlockSize method a Cipher may support
// if it is based on a block-based (or sponge function) cipher.
type cipherBlockSize interface {
	BlockSize() int
}

// Create a new Hash function generically from a message cipher instance,
// which will produce hashes of the specified size.
// If the size parameter is zero, the message cipher's HashSize is used.
func NewHash(cipher func(key []byte) State, size int) Hash {
	ch := &cipherHash{}
	ch.cipher = cipher
	ch.cur = cipher(NoKey)
	if size == 0 {
		size = ch.cur.HashSize()
	}
	ch.size = size
	return ch
}

func (ch *cipherHash) Write(src []byte) (int, error) {
	ch.cur.Partial(nil, nil, src)
	return len(src), nil
}

func (ch *cipherHash) Sum(buf []byte) []byte {

	// Clone the Cipher to leave the original's state unaffected
	c := ch.cur.Clone()
	c.Message(nil, nil, nil) // finalize the message

	// Squeeze out a hash of any requested size.
	buf, hash := util.Grow(buf, ch.size)
	c.Partial(hash, nil, nil)
	return buf
}

func (ch *cipherHash) Reset() {
	ch.cur = ch.cipher(NoKey)
}

func (ch *cipherHash) Size() int {
	return ch.size
}

func (ch *cipherHash) BlockSize() int {
	bs, ok := ch.cur.(cipherBlockSize)
	if !ok {
		return 1 // default for non-block-based ciphers
	}
	return bs.BlockSize()
}
