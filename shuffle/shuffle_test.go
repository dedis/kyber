package shuffle

import (
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/openssl"
	"testing"
)

func TestPairShuffle(t *testing.T) {
	TestShuffle(edwards.NewAES128SHA256Ed25519(false), 10, 1)
}

func Benchmark2PairShuffleP256(b *testing.B) {
	TestShuffle(nist.NewAES128SHA256P256(), 2, b.N)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	TestShuffle(nist.NewAES128SHA256P256(), 10, b.N)
}

func Benchmark10PairShuffleOSSLP256(b *testing.B) {
	TestShuffle(openssl.NewAES128SHA256P256(), 10, b.N)
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
