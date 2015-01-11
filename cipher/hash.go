package cipher

import (
	//"hash"
	"github.com/dedis/crypto/abstract"
	//"github.com/dedis/crypto/util"
)

// Wrapper to use a generic mesage Cipher as a Hash
type cipherHash struct {
	orig,cur abstract.Cipher
	buf []byte
}

/*
func NewHash(c Cipher) hash.Hash {
	ch := &cipherHash{}
	ch.orig = c.Clone(nil)
	ch.cur = c.Clone(nil)
	ch.buf = make([]byte,0,ch.cur.BlockSize())
	return ch
}

func (ch *cipherHash) Write(buf []byte) (int,error) {
	bs := cap(ch.buf)
	ch.cur.Encrypt(nil, buf, ...

	act := len(buf)
	
	for len(buf) > 0 {
		lold := len(ch.buf)
		lnew := lold+len(buf)
		if lold == 0 && lnew >= bs {		// fast path
			for len(buf) >= bs {
				ch.cur.Absorb(buf[:bs], nil, false)
				buf = buf[bs:]
			}
		} else if lnew >= bs {			// filled a block
			n := bs-lold
			ch.buf = append(ch.buf,buf[:n]...)
			ch.cur.Absorb(ch.buf, nil, false)
			ch.buf = ch.buf[:0]
			buf = buf[n:]
		} else {				// incomplete block
			ch.buf = append(ch.buf,buf...)
			break
		}
	}
	return act,nil
}

func (ch *cipherHash) Sum(b []byte) []byte {
	// Clone the sponge state to leave the original one unaffected
	s := ch.cur.Clone()
	bs := s.BlockLen()

	pad := s.Pad(nil,ch.buf)	// pad the final partial block
	if len(pad) > bs {
		s.Absorb(pad[:bs], nil, false)
		pad = pad[bs:]
	}
	s.Absorb(pad, nil, true)

	// Squeeze out a hash of any requested size.
	b,hash := util.Grow(b,s.HashLen())
	for len(hash) > bs {
		s.Squeeze(hash[:bs])
		hash = hash[bs:]
	}
	s.Squeeze(hash)
	return b
}

func (ch *cipherHash) Reset() {
	ch.cur = ch.orig.Clone()
	ch.buf = ch.buf[:0]
}

func (ch *cipherHash) Size() int {
	return ch.cur.HashSize()
}

func (ch *cipherHash) BlockSize() int {
	return cap(ch.buf)
}
*/

