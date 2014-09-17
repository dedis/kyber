package shuffle

import (
	"testing"
	"dissent/crypto"
	"dissent/crypto/openssl"
	"dissent/crypto/edwards"
)

func TestPairShuffle(t *testing.T) {
	TestShuffle(edwards.NewAES128SHA256Ed25519(false), 10)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestShuffle(crypto.NewAES128SHA256P256(), 10)
	}
}

func Benchmark10PairShuffleOSSLP256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestShuffle(openssl.NewAES128SHA256P256(), 10)
	}
}

func Benchmark2PairShuffleEd25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestShuffle(edwards.NewAES128SHA256Ed25519(false), 2)
	}
}

func Benchmark10PairShuffleEd25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestShuffle(edwards.NewAES128SHA256Ed25519(false), 10)
	}
}

func Benchmark100PairShuffleEd25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TestShuffle(edwards.NewAES128SHA256Ed25519(false), 100)
	}
}

