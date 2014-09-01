package bench

import (
	"hash"
	"testing"
	"crypto/cipher"
)


func HashBench(b *testing.B, hash func() hash.Hash) {
	b.SetBytes(1024 * 1024)
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		h := hash()
		for j := 0; j < 1024; j++ {
			h.Write(data)
		}
		h.Sum(nil)
	}
}

// Benchmark a stream cipher.
func StreamCipherBench(b *testing.B, keylen int,
			cipher func([]byte) cipher.Stream) {
	key := make([]byte, keylen)
	b.SetBytes(1024 * 1024)
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		c := cipher(key)
		for j := 0; j < 1024; j++ {
			c.XORKeyStream(data,data)
		}
	}
}

// Benchmark a block cipher operating in counter mode.
func BlockCipherBench(b *testing.B, keylen int,
			bcipher func([]byte) cipher.Block) {
	StreamCipherBench(b, keylen, func(key []byte) cipher.Stream {
		bc := bcipher(key)
		iv := make([]byte,bc.BlockSize())
		return cipher.NewCTR(bc,iv)
	})
}

