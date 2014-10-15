package crypto

import (
	"hash"
	"fmt"
	"io"
	"crypto/cipher"
	"encoding/hex"
)

// Suite is an abstract interface to a full suite of
// public-key and symmetric-key crypto primitives
// chosen to be suited to each other and haver matching security parameters.
// A ciphersuite in this framework basically consists of three components:
// a hash function, a stream cipher, and an abstract group
// for public-key crypto.
//
// This interface adopts hashes and stream ciphers as its
// fundamental symmetric-key crypto abstractions because
// they are conceptually simple and directly complementary in function:
// a hash takes any desired number of input bytes
// and produces a small fixed number of output bytes,
// whereas a stream cipher takes a small fixed number of input bytes
// and produces any desired number of output bytes.
// While stream ciphers can be and often are constructed from block ciphers,
// we treat block ciphers as an implementation detail
// hidden below the abstraction level of this ciphersuite interface.
type Suite interface {

	// Symmetric-key hash function
	HashLen() int
	Hash() hash.Hash

	// Stream cipher and [pseudo-]random bit generator.
	// KeyLen() <= HashLen(), and is typically around half the size
	KeyLen() int
	Stream(key []byte) cipher.Stream

	// Message authentication check (MAC) function
	//MacLen() int
	//Mac(stream cipher.Stream) hash.Hash

	// abstract group for public-key crypto
	Group
}


// Use a given ciphersuite's hash function to hash a byte-slice.
func HashBytes(suite Suite, data []byte) []byte {
	h := suite.Hash()
	h.Write(data)
	return h.Sum(nil)
}

// Create a pseudorandom stream seeded by hashing an arbitrary byte string.
// This can be considered a general key expansion function
// taking an input seed of arbitrary size
// such that the resulting stream depends on every bit of the input.
// Optionally incorporate KeyLen() random bytes from a parent stream as well,
// making the result a hash-indexed substream of the parent stream.
func HashStream(suite Suite, data []byte, parent cipher.Stream) cipher.Stream {
	h := suite.Hash()
	if parent != nil {
		key := make([]byte,suite.KeyLen())
		parent.XORKeyStream(key,key)
		h.Write(key)
	}
	h.Write(data)
	b := h.Sum(nil)
	return suite.Stream(b[:suite.KeyLen()])
}

// Create a pseudorandom stream seeded by hashing a group element
// from the public-key group associated with this ciphersuite.
func PointStream(suite Suite, point Point) cipher.Stream {
	buf := point.Encode()
	return HashStream(suite, buf, nil)
}

// Pull enough bytes for a seed from an existing stream cipher
// to produce a new, derived sub-stream cipher.
// This may be effectively used as a "fork" operator for stream ciphers,
// capable of producing arbitrary trees of stream ciphers that are
// cryptographically independent but pseudo-randomly derived
// from the same root cipher.
func SubStream(suite Suite, s cipher.Stream) cipher.Stream {
	key := make([]byte,suite.KeyLen())
	s.XORKeyStream(key,key)
	return suite.Stream(key)
}


// Create a stream cipher out of a block cipher,
// by running the block cipher in counter mode.
// The initialization vector may be nil to start with a zero IV.
func BlockStream(bc cipher.Block, iv []byte) cipher.Stream {
	if iv == nil {
		iv = make([]byte, bc.BlockSize())
	} else if len(iv) != bc.BlockSize() {
		panic("wrong initialization vector length")
	}
	return cipher.NewCTR(bc,iv)
}


type tracer struct {
	w io.Writer
	s cipher.Stream
}

func (t *tracer) XORKeyStream(dst,src []byte) {
	buf := make([]byte, len(src))
	t.s.XORKeyStream(buf,buf)
	fmt.Printf("TraceStream %p -> %s\n", t, hex.EncodeToString(buf))
	for i := range(buf) {
		dst[i] = src[i] ^ buf[i]
	}
}

// Wrap a stream with a tracer that simply traces its usage for debugging.
// This is useful to determine when and why two pseudorandom streams
// unexpectedly diverge.
func TraceStream(w io.Writer, s cipher.Stream) cipher.Stream {
	return &tracer{w,s}
}


