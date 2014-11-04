package sponge

// Wrapper for using a Sponge as a Stream cipher
type spongeStream struct {
	s Cipher
	buf,avl []byte
}

func (ss *spongeStream) Init(s Cipher) {
	ss.s = s
	ss.buf = make([]byte,s.BlockLen())
}

func (ss *spongeStream) XORKeyStream(dst,src []byte) {
	for len(dst) > 0 {
		if len(ss.avl) == 0 {
			ss.s.Squeeze(ss.buf)	// squeeze out a block
			ss.avl = ss.buf
		}
		var n int
		if src == nil {
			n = copy(dst, ss.avl)
		} else {
			n = len(dst)
			if n > len(ss.avl) {
				n = len(ss.avl)
			}
			for i := 0; i < n; i++ {
				dst[i] = src[i] ^ ss.avl[i]
			}
			src = src[:n]
		}
		dst = dst[:n]
		ss.avl = ss.avl[:n]
	}
}


