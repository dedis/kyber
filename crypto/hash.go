package crypto

// Wrapper to use a Sponge cipher as a Hash
type spongeHash struct {
	orig, cur Sponge
	bs        int
	buf       []byte
}

func (sh *spongeHash) Init(s Sponge) *spongeHash {
	sh.orig = s.Clone()
	sh.cur = s.Clone()
	sh.bs = s.BlockSize()
	sh.buf = make([]byte, 0, bs)
	return sh
}

func (sh *spongeHash) Write(buf []byte) (int, error) {
	bs := sh.bs
	for len(buf) > bs {
		lold := len(sh.buf)
		lnew := lold + len(buf)
		if lold == 0 && lnew >= bs { // fast path
			n := (len(buf) / bs) * bs
			sh.s.Encrypt(nil, buf[:n], true)
			buf = buf[n:]
		} else if lnew >= bs { // filled a block
			n := bs - lold
			sh.buf = append(sh.buf, buf[:n]...)
			sh.s.Encrypt(nil, sh.buf)
			sh.buf = sh.buf[:0]
			buf = buf[n:]
		} else { // incomplete block
			sh.buf = append(sh.buf, buf...)
		}
	}
}

func (sh *spongeHash) Sum(b []byte) []byte {
	// Clone the sponge state to leave the original one unaffected
	s := sh.s.Clone()
	s.Encrypt(nil, []byte{}, false) // pad and complete the current message
	b, hash := grow(b, s.HashLen())
	s.Encrypt(hash, nil) // squeeze bytes to produce the hash
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
	return sh.bs
}
