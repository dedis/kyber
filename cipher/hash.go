package cipher

import (
	"hash"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/util/bytes"
)

// Wrapper to use a generic mesage Cipher as a Hash
type cipherHash struct {
	cipher func(key []byte, options ...interface{}) crypto.Cipher
	cur    crypto.Cipher
	size   int
}

// interface representing an optional BlockSize method a Cipher may support
// if it is based on a block-based (or sponge function) cipher.
type cipherBlockSize interface {
	BlockSize() int
}

func NewHash(cipher func(key []byte, options ...interface{}) crypto.Cipher, size int) hash.Hash {
	ch := &cipherHash{}
	ch.cipher = cipher
	ch.cur = cipher(crypto.NoKey)
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
	buf, hash := bytes.Grow(buf, ch.size)
	c.Partial(hash, nil, nil)
	return buf
}

func (ch *cipherHash) Reset() {
	ch.cur = ch.cipher(crypto.NoKey)
}

func (ch *cipherHash) Size() int {
	return ch.size
}

func (ch *cipherHash) BlockSize() int {
	bs, ok := ch.cur.CipherState.(cipherBlockSize)
	if !ok {
		return 1 // default for non-block-based ciphers
	}
	return bs.BlockSize()
}
