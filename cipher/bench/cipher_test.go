package bench

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/aes"
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/cipher/norx"
	"testing"
)

var buf = make([]byte, 1024*1024)

// benchmarkCipher tests the speed of a Cipher to process a size-byte message.
func benchmarkCipher(b *testing.B, cipher abstract.Cipher, size int) {
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		cipher.Crypt(buf[:size], buf[:size])
	}
}


// 1B messages

func BenchmarkAes128_1B(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher128(), 1)
}
func BenchmarkAes192_1B(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher192(), 1)
}
func BenchmarkAes256_1B(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher256(), 1)
}

func BenchmarkSha3_224_1B(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher224(), 1)
}
func BenchmarkSha3_256_1B(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher256(), 1)
}
func BenchmarkSha3_384_1B(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher384(), 1)
}
func BenchmarkSha3_512_1B(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher512(), 1)
}

func BenchmarkNORX_1B(b *testing.B) {
	benchmarkCipher(b, norx.NewCipher(), 1)
}


// 1K messages

func BenchmarkAes128_1K(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher128(), 1024)
}
func BenchmarkAes192_1K(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher192(), 1024)
}
func BenchmarkAes256_1K(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher256(), 1024)
}

func BenchmarkSha3_224_1K(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher224(), 1024)
}
func BenchmarkSha3_256_1K(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher256(), 1024)
}
func BenchmarkSha3_384_1K(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher384(), 1024)
}
func BenchmarkSha3_512_1K(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher512(), 1024)
}

func BenchmarkNORX_1K(b *testing.B) {
	benchmarkCipher(b, norx.NewCipher(), 1024)
}


// 1M messages

func BenchmarkAes128_1M(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher128(), 1024*1024)
}
func BenchmarkAes192_1M(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher192(), 1024*1024)
}
func BenchmarkAes256_1M(b *testing.B) {
	benchmarkCipher(b, aes.NewCipher256(), 1024*1024)
}

func BenchmarkSha3_224_1M(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher224(), 1024*1024)
}
func BenchmarkSha3_256_1M(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher256(), 1024*1024)
}
func BenchmarkSha3_384_1M(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher384(), 1024*1024)
}
func BenchmarkSha3_512_1M(b *testing.B) {
	benchmarkCipher(b, sha3.NewCipher512(), 1024*1024)
}

func BenchmarkNORX_1M(b *testing.B) {
	benchmarkCipher(b, norx.NewCipher(), 1024*1024)
}

