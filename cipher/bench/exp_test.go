// +build experimental

package bench

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/norx"
	"testing"
)

func BenchmarkNORX_1B(b *testing.B) {
	benchmarkCipher(b, norx.NewCipher(abstract.NoKey), 1)
}
func BenchmarkNORX_1K(b *testing.B) {
	benchmarkCipher(b, norx.NewCipher(abstract.NoKey), 1024)
}
func BenchmarkNORX_1M(b *testing.B) {
	benchmarkCipher(b, norx.NewCipher(abstract.NoKey), 1024*1024)
}

