package shuffle

import (
	"testing"

	"gopkg.in/dedis/crypto.v0/edwards"
	"gopkg.in/dedis/crypto.v0/nist"
)

func TestBiffle(t *testing.T) {
	BiffleTest(edwards.NewAES128SHA256Ed25519(false), 1)
}

func TestPairShuffle(t *testing.T) {
	TestShuffle(edwards.NewAES128SHA256Ed25519(false), 10, 1)
}

func BenchmarkBiffleP256(b *testing.B) {
	BiffleTest(nist.NewAES128SHA256P256(), b.N)
}

func Benchmark2PairShuffleP256(b *testing.B) {
	TestShuffle(nist.NewAES128SHA256P256(), 2, b.N)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	TestShuffle(nist.NewAES128SHA256P256(), 10, b.N)
}

func BenchmarkBiffleEd25519(b *testing.B) {
	BiffleTest(edwards.NewAES128SHA256Ed25519(false), b.N)
}

func Benchmark2PairShuffleEd25519(b *testing.B) {
	TestShuffle(edwards.NewAES128SHA256Ed25519(false), 2, b.N)
}

func Benchmark10PairShuffleEd25519(b *testing.B) {
	TestShuffle(edwards.NewAES128SHA256Ed25519(false), 10, b.N)
}

func Benchmark100PairShuffleEd25519(b *testing.B) {
	TestShuffle(edwards.NewAES128SHA256Ed25519(false), 100, b.N)
}
