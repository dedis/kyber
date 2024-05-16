package shuffle

import (
	"testing"

	"go.dedis.ch/kyber/v4/group/nist"
)

func BenchmarkBiffleP256(b *testing.B) {
	biffleTest(nist.NewBlakeSHA256P256(), b.N)
}

func Benchmark2PairShuffleP256(b *testing.B) {
	pairShuffleTest(nist.NewBlakeSHA256P256(), 2, b.N)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	pairShuffleTest(nist.NewBlakeSHA256P256(), 10, b.N)
}

func Benchmark2Pair2SeqShuffleP256(b *testing.B) {
	sequenceShuffleTest(nist.NewBlakeSHA256P256(), 2, 2, b.N)
}

func Benchmark2Pair10SeqShuffleP256(b *testing.B) {
	sequenceShuffleTest(nist.NewBlakeSHA256P256(), 2, 10, b.N)
}

func Benchmark10Pair10SeqShuffleP256(b *testing.B) {
	sequenceShuffleTest(nist.NewBlakeSHA256P256(), 10, 10, b.N)
}
