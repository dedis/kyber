package abstract

import (
	"hash"
	"crypto/cipher"
	"github.com/dedis/crypto/util"
)

// SpongeCipher is an abstract interface for a sponge cipher primitive
// capable of duplex operation (concurrent absorbinb and squeezing).
type SpongeCipher interface {

	// Encrypt bytes from src to dst, updating the sponge state.
	// If dst == nil, absorbs input without producing output.
	// If src == nil, squeezes output based on an input of zero bytes.
	// If more is false, completes and pads the current message.
	// If more is true, src and dst must be a multiple of BlockSize,
	// and leaves the current message un-padded so that
	// the next Encrypt call will continue the same message.
	// Returns the number of bytes encrypted.
	Encrypt(dst,src []byte, more bool)

	// Decrypt bytes from src to dst, updating the sponge state.
	// Returns the number of bytes decrypted, or an error on failure.
	Decrypt(dst,src []byte, more bool)

	// Create a copy of this SpongeCipher with identical state
	Clone() SpongeCipher

	// Return the sponge cipher's block size: the minimum granularity
	// at which partial, unpadded messages may be processed.
	BlockSize() int

	// Return the recommended size of symmetric cryptographic keys
	// to obtain the full security from this sponge.
	KeyLen() int

/*
	// Encrypt bytes from src to dst, updating the sponge state.
	// If dst == nil, absorbs input without producing output.
	// Returns the number of bytes encrypted, or an error on failure
	// (which happens only if the io.Writer or io.Reader returns an error).
	Encrypt(dst io.Writer, src io.Reader) (int,error)

	// Decrypt bytes from src to dst, updating the sponge state.
	// Returns the number of bytes decrypted, or an error on failure.
	Decrypt(dst io.Writer, src io.Reader) (int,error)
*/

/*
	// Write absorbs message data.
	// Consecutive calls to Write constitute a single message,
	// terminated by the next call to Read, Encrypt, or Decrypt.
	io.Writer

	// Read reads output from the sponge,
	// after consuming the remainder any message absorbed via Write.
	// Reading affects the sponge's state, in contrast with Hash.Sum.
	// Never returns an error.
	io.Reader

	// XORKeyStream uses output from the sponge to encrypt a plaintext.
	cipher.Stream

	// Concurrently absorb a message and produce a cipher-stream.
	// The generated cipher-stream bits may depend on 
	// some, all, or none of the concurrently absorbed message bits.
	// If src != nil, XORs cipher-stream bytes with src into dst.
	// If src == nil, just copies cipher-stream bytes into dst.
	Encrypt(dst,src []byte)
	Decrypt(dst,src []byte)
*/
}

// Sponge wraps a primitive SpongeCipher interface
// with useful functionality and compatibility facilities.
type Sponge struct {
	SpongeCipher
}

// Absorb a message, updating the sponge's state.
func (s Sponge) Absorb(buf []byte) {
	s.Encrypt(nil,buf,false)
}

// Squeeze bytes from the sponge without consuming any input,
// updating the sponge's state.
func (s Sponge) Squeeze(buf []byte) {
	s.Encrypt(buf,nil,false)
}

// Create a Stream cipher that squeezes bytes from this sponge.
// Calls on the resulting Stream update the sponge's state.
func (s Sponge) Stream() cipher.Stream {
	ss := spongeStream{}
	ss.Init(s)
	return &ss
}

// Create a copy of this Sponge with identical state
func (s Sponge) Clone() Sponge {
	return Sponge{s.SpongeCipher.Clone()}
}

// Create a Hash keyed from the sponge's current state.
// Operations on the resulting Hash do NOT affect the original sponge.
func (s Sponge) Hash() hash.Hash {
	sh := spongeHash{}
	sh.Init(s)
	return &sh
}

// Returns the recommended number of bytes to squeeze
// for use as a collision-resistant hash, which is
// twice the sponge's KeyLen to account for birthday attacks.
func (s Sponge) HashLen() int {
	return s.KeyLen() * 2
}



/*	XXX this is probably junk


// Flush any currently ongoing read or write message.
func (c *Cipher) flush() {
	if c.rreq != nil {
		c.rreq <- nil
		c.rreq = nil
		c.rsig = nil
	}
	XXX
}

type squeezer struct {
	c *Cipher
	req chan []byte
	sig chan struct{}
	out []byte
	done bool
}

func (sr *squeezer) init(c *Cipher) {
	sr.c = c
	sr.req = make(chan []byte)
	sr.sig = make(chan struct{})
	go func() {
		c.s.Encrypt(sr,sr)
	}
}

// Called by sponge.Encrypt() to read input message bits, in this case zeros,
// until we get an end-of-read signal.
func (sr *squeezer) Read(buf []byte) (int,error) {
	if sr.done {
		return 0,nil
	}
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}
	return len(buf),nil
}

// Called by sponge.Encrypt() to write output ciphertext,
// which we deposit in whatever byte-slices we are requested to.
func (sr *squeezer) Write(buf []byte) (int,error) {
	act := 0
	for len(buf) > 0 {
		if sr.out == nil {
			sr.out <- sr.req	// get a new output byte-slice
			if sr.out == nil {	// message terminator signal
				sr.done = true
				break
			}
		}
		n := copy(out,buf)
		act += n
		buf = buf[n:]
		sr.out = sr.out[n:]
		if len(sr.out) == 0 {
			sr.sig <- struct{}{}
			sr.out = nil
		}
	}
	return act,nil
}

// Squeeze bytes from the sponge to fill a requested buffer
func (sr *squeezer) Squeeze(buf []byte) int {
	sr.req <- 
}



// Read squeezes output bytes from the sponge.
// Reading affects the sponge's state, in contrast with Hash.Sum.
// Never returns an error.
func (c *Cipher) Read(buf []byte) (int,error) {
	if c.rreq == nil {
		c.flush()
		rq = make(chan []byte)
		sg = make(chan struct{})
		go func() {
			
		}
		c.rreq = rq
		c.rsig = sg
	}

	c.rreq <- buf
	_ <- c.rsig

	return len(buf),nil

	if c.r == nil {
		if c.w != nil {
			XXX
		}
		r,w := io.Pipe()
		l := len(buf)
		go func() {
			c.s.Encrypt(w, zeroReader(-1))
		}
		c.r = r
	}
	return c.r.Read(buf)
}

// Encrypt a message from one byte-slice to another,
// concurrently updating the cipher to depend on all bits of the message,
// such that the final Sponge cipher state may be used for authentication.
// If src == nil, just squeezes pseudo-random bytes into dst.
// If dst == nil, just absorbes the src bytes into the cipher's state.
func (c Cipher) EncryptBytes(dst,src []byte) int {
	var r io.Reader
	var w io.Writer
	if src != nil {
		r = bytes.NewBuffer(src)
	} else {
		r = zeroReader(len(dst))
	}
	if dst != nil {
		w = bytes.NewBuffer(dst[:0])
	}
	n,e := c.Encrypt(w,r)
	if e != nil {		// shouldn't happen
		panic(e.Error())
	}
	return n
}

// Decrypt a message from one byte-slice to another,
// updating the cipher state in the same way that Encrypt does.
func (c Cipher) DecryptBytes(dst,src []byte) {
}

// 
func (c Cipher) XORKeyStream(



// A zeroReader produces a given number of zeros.
// if -1, produces an unlimited number of zeros.
type zeroReader int

func (zr *zeroReader) Read(p []byte) (n int, err error) {
	n = len(p)
	if n > *zr && *zr >= 0 {
		n = *zr
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	*zr -= n
}

*/



// Wrapper for using a Sponge as a Stream cipher
type spongeStream struct {
	s Sponge
	buf,avl []byte
}

func (ss *spongeStream) Init(s Sponge) {
	ss.s = s
	ss.buf = make([]byte,s.BlockSize())
}

func (ss *spongeStream) XORKeyStream(dst,src []byte) {
	for len(dst) > 0 {
		if len(ss.avl) == 0 {
			ss.s.Encrypt(ss.buf,nil,true)	// squeeze out a block
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



// Wrapper to use a Sponge cipher as a Hash
type spongeHash struct {
	orig,cur Sponge
	bs int
	buf []byte
}

func (sh *spongeHash) Init(s Sponge) *spongeHash {
	sh.orig = s.Clone()
	sh.cur = s.Clone()
	sh.bs = s.BlockSize()
	sh.buf = make([]byte,0,sh.bs)
	return sh
}

func (sh *spongeHash) Write(buf []byte) (int,error) {
	bs := sh.bs
	act := len(buf)
	for len(buf) > bs {
		lold := len(sh.buf)
		lnew := lold+len(buf)
		if lold == 0 && lnew >= bs {		// fast path
			n := (len(buf)/bs)*bs
			sh.cur.Encrypt(nil,buf[:n],true)
			buf = buf[n:]
		} else if lnew >= bs {			// filled a block
			n := bs-lold
			sh.buf = append(sh.buf,buf[:n]...)
			sh.cur.Encrypt(nil,sh.buf,true)
			sh.buf = sh.buf[:0]
			buf = buf[n:]
		} else {				// incomplete block
			sh.buf = append(sh.buf,buf...)
		}
	}
	return act,nil
}

func (sh *spongeHash) Sum(b []byte) []byte {
	// Clone the sponge state to leave the original one unaffected
	s := sh.cur.Clone()
	s.Encrypt(nil,sh.buf,false)	// pad and complete the current message
	b,hash := util.Grow(b,s.HashLen())
	s.Encrypt(hash,nil,false)	// squeeze bytes to produce the hash
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

