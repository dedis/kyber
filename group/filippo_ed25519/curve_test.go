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

//func TestSuite(t *testing.T) { test.SuiteTest(t, tSuite) }

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

func BenchmarkScalarAdd(b *testing.B) { groupBench.ScalarAdd(b.N) }
func BenchmarkScalarSub(b *testing.B) { groupBench.ScalarSub(b.N) }
func BenchmarkScalarNeg(b *testing.B) { groupBench.ScalarNeg(b.N) }
func BenchmarkScalarMul(b *testing.B) { groupBench.ScalarMul(b.N) }
func BenchmarkScalarDiv(b *testing.B) { groupBench.ScalarDiv(b.N) }
func BenchmarkScalarInv(b *testing.B) { groupBench.ScalarInv(b.N) }

func BenchmarkPointAdd(b *testing.B)     { groupBench.PointAdd(b.N) }
func BenchmarkPointSub(b *testing.B)     { groupBench.PointSub(b.N) }
func BenchmarkPointNeg(b *testing.B)     { groupBench.PointNeg(b.N) }
func BenchmarkPointMul(b *testing.B)     { groupBench.PointMul(b.N) }
func BenchmarkPointBaseMul(b *testing.B) { groupBench.PointBaseMul(b.N) }

//func TestScalarMulAdd(t *testing.T) {
//	s1 := new(scalar).Pick(random.New())
//	s2 := new(scalar).SetInt64(2)
//	s3 := new(scalar).Mul(s1, s2)
//
//	s4 := new(scalar).Add(s1, s1)
//
//	if !s3.Equal(s4) {
//		t.Fail()
//	}
//}

func BenchmarkCTScalarMul(b *testing.B) {
	benchScalarMul(b, tSuite.Scalar)
}
