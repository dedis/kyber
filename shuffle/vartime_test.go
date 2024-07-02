package shuffle

import (
	"testing"

	"go.dedis.ch/kyber/v4/group/p256"
)

func BenchmarkBiffleP256(b *testing.B) {
	biffleTest(p256.NewBlakeSHA256P256(), b.N)
}

func Benchmark2PairShuffleP256(b *testing.B) {
	pairShuffleTest(p256.NewBlakeSHA256P256(), 2, b.N)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	pairShuffleTest(p256.NewBlakeSHA256P256(), 10, b.N)
}

func Benchmark2Pair2SeqShuffleP256(b *testing.B) {
	sequenceShuffleTest(p256.NewBlakeSHA256P256(), 2, 2, b.N)
}

func Benchmark2Pair10SeqShuffleP256(b *testing.B) {
	sequenceShuffleTest(p256.NewBlakeSHA256P256(), 2, 10, b.N)
}

func Benchmark10Pair10SeqShuffleP256(b *testing.B) {
	sequenceShuffleTest(p256.NewBlakeSHA256P256(), 10, 10, b.N)
}
