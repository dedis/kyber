package filippo_ed25519

import (
	"fmt"
	"go.dedis.ch/kyber/v3/util/test"
	"testing"

	"go.dedis.ch/kyber/v3"

	filippo_ed25519 "filippo.io/edwards25519"
)

var tSuite = NewBlakeSHA256FilippoEd25519()
var groupBench = test.NewGroupBench(tSuite)

func TestSuite(t *testing.T) { test.SuiteTest(t, tSuite) }

func TestFilippo(t *testing.T) {
	var point = filippo_ed25519.NewGeneratorPoint()

	fmt.Println(point.Bytes())
}

func benchScalarMul(b *testing.B, new func() kyber.Scalar) {
	var seed = tSuite.XOF([]byte("hello world"))
	s1 := new()
	s2 := new()
	s3 := new()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Mul(s1, s2)
	}
}

func BenchmarkScalarMul(b *testing.B) { groupBench.ScalarMul(b.N) }
func BenchmarkPointMul(b *testing.B)  { groupBench.PointMul(b.N) }

func BenchmarkCTScalarMul(b *testing.B) {
	benchScalarMul(b, tSuite.Scalar)
}
