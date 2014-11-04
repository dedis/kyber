package sponge

import (
	"github.com/dedis/crypto/util"
)

// Wrapper to use a sponge cipher as a Hash
type spongeHash struct {
	orig,cur Cipher
	buf []byte
}

func (sh *spongeHash) Init(s Cipher) *spongeHash {
	sh.orig = s.Clone()
	sh.cur = s.Clone()
	sh.buf = make([]byte,0,s.BlockLen())
	return sh
}

func (sh *spongeHash) Write(buf []byte) (int,error) {
	bs := sh.cur.BlockLen()
	act := len(buf)
	for len(buf) > 0 {
		lold := len(sh.buf)
		lnew := lold+len(buf)
		if lold == 0 && lnew >= bs {		// fast path
			for len(buf) >= bs {
				sh.cur.Absorb(buf[:bs], nil, false)
				buf = buf[bs:]
			}
		} else if lnew >= bs {			// filled a block
			n := bs-lold
			sh.buf = append(sh.buf,buf[:n]...)
			sh.cur.Absorb(sh.buf, nil, false)
			sh.buf = sh.buf[:0]
			buf = buf[n:]
		} else {				// incomplete block
			sh.buf = append(sh.buf,buf...)
			break
		}
	}
	return act,nil
}

func (sh *spongeHash) Sum(b []byte) []byte {
	// Clone the sponge state to leave the original one unaffected
	s := sh.cur.Clone()
	bs := s.BlockLen()

	pad := s.Pad(nil,sh.buf)	// pad the final partial block
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

func (sh *spongeHash) Reset() {
	sh.cur = sh.orig.Clone()
	sh.buf = sh.buf[:0]
}

func (sh *spongeHash) Size() int {
	return sh.cur.HashLen()
}

func (sh *spongeHash) BlockSize() int {
	return sh.cur.BlockLen()
}

