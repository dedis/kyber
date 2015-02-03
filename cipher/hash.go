package cipher

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/util"
	"hash"
)

// Wrapper to use a generic mesage Cipher as a Hash
type cipherHash struct {
	cipher func(key []byte, options ...interface{}) abstract.Cipher
	cur    abstract.Cipher
	size   int
}

func NewHash(cipher func(key []byte, options ...interface{}) abstract.Cipher, size int) hash.Hash {
	ch := &cipherHash{}
	ch.cipher = cipher
	ch.cur = cipher(abstract.NoKey)
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
	ch.cur = ch.cipher(abstract.NoKey)
}

func (ch *cipherHash) Size() int {
	return ch.size
}

func (ch *cipherHash) BlockSize() int {
	return ch.cur.BlockSize()
}
