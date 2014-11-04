package sponge

import (
	//"hash"
	//"crypto/cipher"
	//"github.com/dedis/crypto/util"
)

// Cipher is an abstract interface for a primitive sponge cipher.
type Cipher interface {

	// Absorb up to BlockLen data bytes from src,
	// and up to StateLen bytes of state-indexing material from idx.
	// The last flag indicates the last block of a padded message.
	Absorb(src,idx []byte, last bool)

	// Squeeze up to BlockLen data bytes into dst,
	// updating the state if no unconsumed output block is available.
	Squeeze(dst []byte)

	// XXX combine Squeeze with Absorb?

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
	Clone() Cipher
}


/*

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
		s.Absorb(src[:bs], nil, false)
		src = src[bs:]
	}

	// Pad and absorb last input block, to produce 1 or 2 blocks
	pad := s.Pad(nil,src)
	if len(pad) > bs {
		s.Absorb(pad[:bs], nil, false)
		pad = pad[bs:]
	}
	s.Absorb(pad, nil, true)
}

// Squeeze any number of bytes from the sponge without consuming any input,
// updating the sponge's state in the process.
// Squeezing a b1-byte cipherstream then a b2-byte cipherstream yields
// a different state than squeezing a single (b1+b2)-byte cipherstream.
func (s Sponge) Squeeze(dst []byte) {
	bs := s.BlockLen()

	// Squeeze whole output blocks
	for len(dst) >= bs {
		s.Squeeze(dst[:bs])
		dst = dst[bs:]
	}

	// Partial last block
	if len(dst) > 0 {
		buf := make([]byte, bs)
		s.Squeeze(buf)
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
		s.Squeeze(buf[:bs])		// produce cipherstream
		s.Absorb(src[:bs], nil, false)	// absorb plaintext
		xorOut(dst[:bs], src[:bs], buf[:bs])	// XOR-encrypt
		src = src[bs:]
		dst = dst[bs:]
	}

	// Pad the final message block
	padsrc := s.Pad(nil,src)			// padded src
	padbuf := make([]byte, len(padsrc))		// padded dst
	paddst := padbuf

	if len(padsrc) > bs {
		s.Squeeze(buf[:bs])		// produce cipherstream
		s.Absorb(padsrc[:bs], nil, false)	// absorb plaintext
		xorOut(paddst[:bs], padsrc[:bs], buf[:bs]) // XOR-encrypt
		padsrc = padsrc[bs:]
		paddst = paddst[bs:]
	}

	s.Squeeze(buf[:bs])		// produce cipherstream
	s.Absorb(padsrc[:bs], nil, true)	// absorb last plaintext block
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
		s.Squeeze(buf[:bs])		// produce cipherstream
		xorOut(dst[:bs], src[:bs], buf[:bs])	// XOR-decrypt
		s.Absorb(dst[:bs], nil, false)	// absorb plaintext
		src = src[bs:]
		dst = dst[bs:]
	}

	// Pad the final message block
	padsrc := s.Pad(nil,src)			// padded src
	padbuf := make([]byte, len(padsrc))		// padded dst
	paddst := padbuf

	if len(padsrc) > bs {
		s.Squeeze(buf[:bs])		// produce cipherstream
		xorOut(paddst[:bs], padsrc[:bs], buf[:bs]) // XOR-decrypt
		s.Absorb(paddst[:bs], nil, false)	// absorb plaintext
		padsrc = padsrc[bs:]
		paddst = paddst[bs:]
	}

	s.Squeeze(buf[:bs])		// produce cipherstream
	xorOut(paddst[:bs],padsrc[:bs],buf[:bs]) // XOR-decrypt
	s.Absorb(paddst[:bs], nil, true)	// absorb last plaintext block

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

*/
