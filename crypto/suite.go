package crypto

import (
	"hash"
	"time"
	"fmt"
	"crypto/cipher"
	"encoding/hex"
)

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

type Hasher interface {
	Hash(data []byte)
}


// Create a pseudorandom stream seeded by hashing an arbitrary byte string
func HashStream(suite Suite, data []byte) cipher.Stream {
	h := suite.Hash()
	h.Write(data)
	b := h.Sum(nil)
	return suite.Stream(b[:suite.KeyLen()])
}

// Create a pseudorandom stream seeded by hashing a group element
func PointStream(suite Suite, point Point) cipher.Stream {
	return HashStream(suite, point.Encode())
}

// Pull enough bytes for a seed from an existing cipher
// to produce a new, derived sub-cipher
func SubStream(suite Suite, s cipher.Stream) cipher.Stream {
	key := make([]byte,suite.KeyLen())
	s.XORKeyStream(key,key)
	return suite.Stream(key)
}


func TestSuite(suite Suite) {

	// Try hashing something
	h := suite.Hash()
	l := suite.HashLen()
	println("HashLen: ",l)
	h.Write([]byte("abc"))
	hb := h.Sum(nil)
	println("Hash:")
	println(hex.Dump(hb))
	if h.Size() != l || len(hb) != l {
		panic("inconsistent hash output length")
	}

	// Generate some pseudorandom bits
	s := suite.Stream(hb[0:suite.KeyLen()])
	sb := make([]byte,128)
	s.XORKeyStream(sb,sb)
	println("Stream:")
	println(hex.Dump(sb))

	// Generate a sub-stream
	ss := SubStream(suite,s)
	sb = make([]byte,128)
	ss.XORKeyStream(sb,sb)
	println("SubStream:")
	println(hex.Dump(sb))

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

func BenchSuite(suite Suite) {

	// Stream benchmark
	benchStream(suite, 16)
	benchStream(suite, 1024)
	benchStream(suite, 1024*1024)

	// Benchmark the abstract group functions
	BenchGroup(suite)
}

