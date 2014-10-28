package abstract

import (
	"hash"
	"crypto/cipher"
	"github.com/dedis/crypto/util"
)

// SpongeCipher is an abstract interface for a primitive sponge cipher.
type SpongeCipher interface {

/*
	// Encrypt bytes from src to dst, updating the sponge state.
	// If dst == nil, absorbs input without producing output.
	// If src == nil, squeezes output based on an input of zero bytes.
	// If more is false, completes and pads the current message.
	// If more is true, src and dst must be a multiple of BlockLen,
	// and leaves the current message un-padded so that
	// the next Encrypt call will continue the same message.
	// Returns the number of bytes encrypted.
	Encrypt(dst,src []byte, more bool)

	// Decrypt bytes from src to dst, updating the sponge state.
	// Returns the number of bytes decrypted, or an error on failure.
	Decrypt(dst,src []byte, more bool)
*/

	// Absorb up to BlockLen data bytes from src,
	// and up to StateLen bytes of state-indexing material from idx.
	// The last flag indicates the last block of a padded message.
	AbsorbBlock(src,idx []byte, last bool)

	// Squeeze up to BlockLen data bytes into dst,
	// updating the state if no unconsumed output block is available.
	SqueezeBlock(dst []byte)

	// Pad the variable-length input src, of size up to one block,
	// into a returned slice containing exactly one or two blocks.
	// Pads into buf if buf is large enough.
	Pad(buf,src []byte) []byte

	// Return the number of data bytes the sponge can aborb in one block.
	BlockLen() int

	// Return the sponge's secret state capacity in bytes.
	StateLen() int

	// Return the recommended size of hash outputs for full security.
	HashLen() int

	// Create a copy of this SpongeCipher with identical state
	Clone() SpongeCipher

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
	SpongeCipher		// Primitive sponge cipher
}

// Absorb an arbitrary-length message, updating the sponge's state.
// Absorbing two messages m1 followed by m2 yields a different state
// than absorbing the concatenation of m1 and m2.
func (s Sponge) Absorb(src []byte) {
	bs := s.BlockLen()

	// Absorb whole input blocks
	for len(src) > bs {
		s.AbsorbBlock(src[:bs], nil, false)
		src = src[bs:]
	}

	// Pad and absorb last input block, to produce 1 or 2 blocks
	pad := s.Pad(nil,src)
	if len(pad) > bs {
		s.AbsorbBlock(pad[:bs], nil, false)
		pad = pad[bs:]
	}
	s.AbsorbBlock(pad, nil, true)
}

// Squeeze any number of bytes from the sponge without consuming any input,
// updating the sponge's state in the process.
// Squeezing a b1-byte cipherstream then a b2-byte cipherstream yields
// a different state than squeezing a single (b1+b2)-byte cipherstream.
func (s Sponge) Squeeze(dst []byte) {
	bs := s.BlockLen()

	// Squeeze whole output blocks
	for len(dst) >= bs {
		s.SqueezeBlock(dst[:bs])
		dst = dst[bs:]
	}

	// Partial last block
	if len(dst) > 0 {
		buf := make([]byte, bs)
		s.SqueezeBlock(buf)
		copy(dst,buf)
	}
}

func xorOut(dst,src,buf []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = src[i] ^ buf[i]
	}
}

// Encrypt message from src to dst, and absorb it into the sponge state.
// Subsequently squeezed bytes may be used as an authenticator.
func (s Sponge) Encrypt(dst,src []byte) {
	bs := s.BlockLen()
	buf := make([]byte, bs)

	// Encrypt complete message blocks
	for len(src) >= bs {
		s.SqueezeBlock(buf[:bs])		// produce cipherstream
		s.AbsorbBlock(src[:bs], nil, false)	// absorb plaintext
		xorOut(dst[:bs], src[:bs], buf[:bs])	// XOR-encrypt
		src = src[bs:]
		dst = dst[bs:]
	}

	// Pad the final message block
	padsrc := s.Pad(nil,src)			// padded src
	padbuf := make([]byte, len(padsrc))		// padded dst
	paddst := padbuf

	if len(padsrc) > bs {
		s.SqueezeBlock(buf[:bs])		// produce cipherstream
		s.AbsorbBlock(padsrc[:bs], nil, false)	// absorb plaintext
		xorOut(paddst[:bs], padsrc[:bs], buf[:bs]) // XOR-encrypt
		padsrc = padsrc[bs:]
		paddst = paddst[bs:]
	}

	s.SqueezeBlock(buf[:bs])		// produce cipherstream
	s.AbsorbBlock(padsrc[:bs], nil, true)	// absorb last plaintext block
	xorOut(paddst[:bs], padsrc[:bs], buf[:bs]) // XOR-encrypt

	copy(dst,padbuf)				// remaining output
}

// Decrypt bytes from src to dst, updating the sponge state.
// Returns the number of bytes decrypted, or an error on failure.
func (s Sponge) Decrypt(dst,src []byte) {
	bs := s.BlockLen()
	buf := make([]byte, bs)

	// Decrypt complete message blocks
	for len(src) >= bs {
		s.SqueezeBlock(buf[:bs])		// produce cipherstream
		xorOut(dst[:bs], src[:bs], buf[:bs])	// XOR-decrypt
		s.AbsorbBlock(dst[:bs], nil, false)	// absorb plaintext
		src = src[bs:]
		dst = dst[bs:]
	}

	// Pad the final message block
	padsrc := s.Pad(nil,src)			// padded src
	padbuf := make([]byte, len(padsrc))		// padded dst
	paddst := padbuf

	if len(padsrc) > bs {
		s.SqueezeBlock(buf[:bs])		// produce cipherstream
		xorOut(paddst[:bs], padsrc[:bs], buf[:bs]) // XOR-decrypt
		s.AbsorbBlock(paddst[:bs], nil, false)	// absorb plaintext
		padsrc = padsrc[bs:]
		paddst = paddst[bs:]
	}

	s.SqueezeBlock(buf[:bs])		// produce cipherstream
	xorOut(paddst[:bs],padsrc[:bs],buf[:bs]) // XOR-decrypt
	s.AbsorbBlock(paddst[:bs], nil, true)	// absorb last plaintext block

	copy(dst,padbuf)				// remaining output
}

// Create a Stream cipher that squeezes bytes from this sponge.
// Calls on the resulting Stream update the sponge's state.
func (s Sponge) Stream() cipher.Stream {
	ss := spongeStream{}
	ss.Init(s)
	return &ss
}

// Create a copy of this Sponge with identical state.
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



// Wrapper for using a Sponge as a Stream cipher
type spongeStream struct {
	s Sponge
	buf,avl []byte
}

func (ss *spongeStream) Init(s Sponge) {
	ss.s = s
	ss.buf = make([]byte,s.BlockLen())
}

func (ss *spongeStream) XORKeyStream(dst,src []byte) {
	for len(dst) > 0 {
		if len(ss.avl) == 0 {
			ss.s.SqueezeBlock(ss.buf)	// squeeze out a block
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
	buf []byte
}

func (sh *spongeHash) Init(s Sponge) *spongeHash {
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
	s := sh.cur.Clone()
	bs := s.BlockLen()

	pad := s.Pad(nil,sh.buf)	// pad the final partial block
	if len(pad) > bs {
		s.AbsorbBlock(pad[:bs], nil, false)
		pad = pad[bs:]
	}
	s.AbsorbBlock(pad, nil, true)

	// Squeeze out a hash of any requested size.
	b,hash := util.Grow(b,s.HashLen())
	for len(hash) > bs {
		s.SqueezeBlock(hash[:bs])
		hash = hash[bs:]
	}
	s.SqueezeBlock(hash)
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

