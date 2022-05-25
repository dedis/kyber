package filippo_ed25519

import (
<<<<<<< HEAD
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/test"
	"math"
	"testing"
=======
	"fmt"
	"go.dedis.ch/kyber/v3/util/test"
	"testing"

	"go.dedis.ch/kyber/v3"

	filippo_ed25519 "filippo.io/edwards25519"
>>>>>>> Docs added and filippo integration initiated
)

var tSuite = NewBlakeSHA256FilippoEd25519()
var groupBench = test.NewGroupBench(tSuite)

func TestSuite(t *testing.T) { test.SuiteTest(t, tSuite) }

<<<<<<< HEAD
func TestCurve_NewKey(t *testing.T) {
	group := Curve{}
	stream := tSuite.RandomStream()

	for i := 0.0; i < math.Pow(10, 6); i++ {
		s := group.NewKey(stream).(*Scalar)

		// little-endian check of a multiple of 8
		b, _ := s.MarshalBinary()
		assert.Equal(t, uint8(0), b[0]&7)
	}
}

func BenchmarkScalarAdd(b *testing.B)    { groupBench.ScalarAdd(b.N) }
func BenchmarkScalarSub(b *testing.B)    { groupBench.ScalarSub(b.N) }
func BenchmarkScalarNeg(b *testing.B)    { groupBench.ScalarNeg(b.N) }
func BenchmarkScalarMul(b *testing.B)    { groupBench.ScalarMul(b.N) }
func BenchmarkScalarDiv(b *testing.B)    { groupBench.ScalarDiv(b.N) }
func BenchmarkScalarInv(b *testing.B)    { groupBench.ScalarInv(b.N) }
func BenchmarkScalarPick(b *testing.B)   { groupBench.ScalarPick(b.N) }
func BenchmarkScalarEncode(b *testing.B) { groupBench.ScalarEncode(b.N) }
func BenchmarkScalarDecode(b *testing.B) { groupBench.ScalarDecode(b.N) }

func BenchmarkPointAdd(b *testing.B)     { groupBench.PointAdd(b.N) }
func BenchmarkPointSub(b *testing.B)     { groupBench.PointSub(b.N) }
func BenchmarkPointNeg(b *testing.B)     { groupBench.PointNeg(b.N) }
func BenchmarkPointMul(b *testing.B)     { groupBench.PointMul(b.N) }
func BenchmarkPointBaseMul(b *testing.B) { groupBench.PointBaseMul(b.N) }
func BenchmarkPointPick(b *testing.B)    { groupBench.PointPick(b.N) }
func BenchmarkPointEncode(b *testing.B)  { groupBench.PointEncode(b.N) }
func BenchmarkPointDecode(b *testing.B)  { groupBench.PointDecode(b.N) }
=======
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
>>>>>>> Docs added and filippo integration initiated
