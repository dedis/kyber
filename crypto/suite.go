package crypto

import (
	"hash"
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


// Pull enough bytes for a seed from an existing cipher
// to produce a new, derived sub-cipher
func SubStream(suite Suite,s cipher.Stream) cipher.Stream {
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


