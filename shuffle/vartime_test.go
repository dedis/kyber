// +build vartime

package shuffle

import (
	"testing"

	"gopkg.in/dedis/kyber.v1/group/nist"
)

func BenchmarkBiffleP256(b *testing.B) {
	BiffleTest(nist.NewAES128SHA256P256(), b.N)
}

func Benchmark2PairShuffleP256(b *testing.B) {
	TestShuffle(nist.NewAES128SHA256P256(), 2, b.N)
}

func Benchmark10PairShuffleP256(b *testing.B) {
	TestShuffle(nist.NewAES128SHA256P256(), 10, b.N)
}
