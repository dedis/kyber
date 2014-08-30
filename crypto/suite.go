package crypto

import (
	"hash"
	"time"
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

	// abstract group for public-key crypto
	Group
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


// Apply a standard set of validation tests to a ciphersuite.
func TestSuite(suite Suite) {

	// Try hashing something
	h := suite.Hash()
	l := suite.HashLen()
	//println("HashLen: ",l)
	h.Write([]byte("abc"))
	hb := h.Sum(nil)
	//println("Hash:")
	//println(hex.Dump(hb))
	if h.Size() != l || len(hb) != l {
		panic("inconsistent hash output length")
	}

	// Generate some pseudorandom bits
	s := suite.Stream(hb[0:suite.KeyLen()])
	sb := make([]byte,128)
	s.XORKeyStream(sb,sb)
	//println("Stream:")
	//println(hex.Dump(sb))

	// Generate a sub-stream
	ss := SubStream(suite,s)
	sb = make([]byte,128)
	ss.XORKeyStream(sb,sb)
	//println("SubStream:")
	//println(hex.Dump(sb))

	// Test the public-key group arithmetic
	TestGroup(suite)
}

func benchStream(suite Suite, len int) {
	buf := make([]byte,len)

	totMB := 10
	iters := totMB * 1024*1024 / len

	// Stream benchmark
	s := SubStream(suite, RandomStream)
	beg := time.Now()
	for i := 1; i < iters; i++ {
		s.XORKeyStream(buf,buf)
	}
	end := time.Now()
	fmt.Printf("Stream %d bytes: %f MB/sec\n", len,
			float64(totMB) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Hash benchmark
	h := suite.Hash()
	beg = time.Now()
	for i := 1; i < iters; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(nil)
	}
	end = time.Now()
	fmt.Printf("Hash %d bytes: %f MB/sec\n", len,
			float64(totMB) /
			(float64(end.Sub(beg)) / 1000000000.0))

}

// Run a Suite through a set of basic microbenchmarks.
func BenchSuite(suite Suite) {

	// Stream benchmark
	benchStream(suite, 16)
	benchStream(suite, 1024)
	benchStream(suite, 1024*1024)

	// Benchmark the abstract group functions
	BenchGroup(suite)
}

