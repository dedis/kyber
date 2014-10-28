package blake2

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	//"crypto/cipher"
	//"crypto/rc4"
	//"crypto/aes"
	"hash"
	"testing"
	//"code.google.com/p/go.crypto/twofish"
)

func benchmarkHash(b *testing.B, hash func() hash.Hash) {
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

func BenchmarkBlake2B(b *testing.B) {
	benchmarkHash(b, NewBlake2b)
}

func BenchmarkMD5(b *testing.B) {
	benchmarkHash(b, md5.New)
}

func BenchmarkSHA1(b *testing.B) {
	benchmarkHash(b, sha1.New)
}

func BenchmarkSHA256(b *testing.B) {
	benchmarkHash(b, sha256.New)
}

func BenchmarkSHA512(b *testing.B) {
	benchmarkHash(b, sha512.New)
}



/*
func benchmarkStream(b *testing.B, cipher func([]byte) cipher.Stream, keylen int) {
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

func benchmarkCTR(b *testing.B, bcipher func([]byte) (cipher.Block,error), keylen int) {
	benchmarkStream(b, func(key []byte) cipher.Stream {
		bc,_ := bcipher(key)
		iv := make([]byte,bc.BlockSize())
		return cipher.NewCTR(bc,iv)
	}, keylen)
}

func BenchmarkBlake2BStream(b *testing.B) {
	benchmarkStream(b, NewBlake2BStream, aes.BlockSize)
}

func BenchmarkRC4(b *testing.B) {
	benchmarkStream(b, func(key []byte) cipher.Stream {
		c,_ := rc4.NewCipher(key)
		return c
	}, 256)
}

func BenchmarkAES128(b *testing.B) {
	benchmarkCTR(b, aes.NewCipher, 16)
}

func BenchmarkAES192(b *testing.B) {
	benchmarkCTR(b, aes.NewCipher, 24)
}

func BenchmarkAES256(b *testing.B) {
	benchmarkCTR(b, aes.NewCipher, 32)
}

func BenchmarkTwofish128(b *testing.B) {
	benchmarkCTR(b, func(key []byte) (cipher.Block,error) {
		return twofish.NewCipher(key)
	}, 16)
}

func BenchmarkTwofish192(b *testing.B) {
	benchmarkCTR(b, func(key []byte) (cipher.Block,error) {
		return twofish.NewCipher(key)
	}, 24)
}

func BenchmarkTwofish256(b *testing.B) {
	benchmarkCTR(b, func(key []byte) (cipher.Block,error) {
		return twofish.NewCipher(key)
	}, 32)
}
*/

