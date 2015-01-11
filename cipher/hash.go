package cipher

import (
	"hash"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/util"
)

// Wrapper to use a generic mesage Cipher as a Hash
type cipherHash struct {
	cipher func() abstract.Cipher
	cur abstract.Cipher
	size int
}

func NewHash(cipher func() abstract.Cipher, size int) hash.Hash {
	ch := &cipherHash{}
	ch.cipher = cipher
	ch.cur = cipher()
	ch.size = size
	return ch
}

func (ch *cipherHash) Write(src []byte) (int,error) {
	ch.cur.Encrypt(nil, src, abstract.More)
	return len(src), nil
}

func (ch *cipherHash) Sum(buf []byte) []byte {

	// Clone the Cipher to leave the original's state unaffected
	c := ch.cur.Clone(nil)
	c.Encrypt(nil, nil)	// finalize the message

	// Squeeze out a hash of any requested size.
	buf,hash := util.Grow(buf, ch.size)
	c.Encrypt(hash, nil)
	return buf
}

func (ch *cipherHash) Reset() {
	ch.cur = ch.cipher()
}

func (ch *cipherHash) Size() int {
	return ch.size
}

func (ch *cipherHash) BlockSize() int {
	return ch.cur.BlockSize()
}

