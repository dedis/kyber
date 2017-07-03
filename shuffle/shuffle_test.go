package shuffle

import (
	"testing"

	"gopkg.in/dedis/kyber.v1/group/edwards25519"
)

func TestBiffle(t *testing.T) {
	BiffleTest(edwards25519.NewAES128SHA256Ed25519(false), 1)
}

func TestPairShuffle(t *testing.T) {
	TestShuffle(edwards25519.NewAES128SHA256Ed25519(false), 10, 1)
}

func BenchmarkBiffleEd25519(b *testing.B) {
	BiffleTest(edwards25519.NewAES128SHA256Ed25519(false), b.N)
}

func Benchmark2PairShuffleEd25519(b *testing.B) {
	TestShuffle(edwards25519.NewAES128SHA256Ed25519(false), 2, b.N)
}

func Benchmark10PairShuffleEd25519(b *testing.B) {
	TestShuffle(edwards25519.NewAES128SHA256Ed25519(false), 10, b.N)
}

func Benchmark100PairShuffleEd25519(b *testing.B) {
	TestShuffle(edwards25519.NewAES128SHA256Ed25519(false), 100, b.N)
}
