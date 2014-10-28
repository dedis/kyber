package blake2

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/util"
)

type spongeImpl interface {
	abstract.SpongeCipher		// Standard sponge cipher interface
	Hash(buf []byte)		// Read BLAKE2b hash state into hash
}

// Wrapper to use a Blake2b sponge cipher as a Hash
type spongeHash struct {
	orig,cur spongeImpl
	buf []byte
}

func (sh *spongeHash) Init(s spongeImpl) *spongeHash {
	sh.orig = s.Clone().(spongeImpl)
	sh.cur = s.Clone().(spongeImpl)
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
				sh.cur.AbsorbBlock(buf[:bs], nil, false)
				buf = buf[bs:]
			}
		} else if lnew >= bs {			// filled a block
			n := bs-lold
			sh.buf = append(sh.buf,buf[:n]...)
			sh.cur.AbsorbBlock(sh.buf, nil, false)
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
	s := sh.cur.Clone().(spongeImpl)
	bs := s.BlockLen()

	pad := s.Pad(nil,sh.buf)	// pad the final partial block
	if len(pad) > bs {
		s.AbsorbBlock(pad[:bs], nil, false)
		pad = pad[bs:]
	}
	s.AbsorbBlock(pad, nil, true)

	// Read the BLAKE2b state to produce the hash.
	b,hash := util.Grow(b,s.HashLen())
	s.Hash(hash)
	return b
}

func (sh *spongeHash) Reset() {
	sh.cur = sh.orig.Clone().(spongeImpl)
	sh.buf = sh.buf[:0]
}

func (sh *spongeHash) Size() int {
	return sh.cur.HashLen()
}

func (sh *spongeHash) BlockSize() int {
	return sh.cur.BlockLen()
}

