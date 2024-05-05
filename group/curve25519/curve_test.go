package curve25519

import (
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/test"
)

var testSuite = NewBlakeSHA256Curve25519(false)

// Test each curve implementation of the Ed25519 curve.

func TestProjective25519(t *testing.T) {
	test.GroupTest(t, new(ProjectiveCurve).Init(Param25519(), false))
}

func TestExtended25519(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param25519(), false))
}

func TestEd25519(t *testing.T) {
	test.GroupTest(t, new(edwards25519.Curve))
}

// Test the Extended coordinates implementation of each curve.

func Test1174(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param1174(), false))
}

func Test25519(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param25519(), false))
}

func TestE382(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(ParamE382(), false))
}

func Test4147(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param41417(), false))
}

func TestE521(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(ParamE521(), false))
}

func TestSetBytesBE(t *testing.T) {
	g := new(ExtendedCurve).Init(ParamE521(), false)
	s := g.Scalar()
	s.SetBytes([]byte{0, 1, 2, 3})
	// 010203 because initial 0 is trimmed in String(), and 03 (last byte of BE) ends up
	// in the LSB of the bigint.
	if s.String() != "010203" {
		t.Fatal("unexpected result from String():", s.String())
	}
}

// Test the full-group-order Extended coordinates versions of each curve
// for which a full-group-order base point is defined.

func TestFullOrder1174(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param1174(), true))
}

func TestFullOrder25519(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param25519(), true))
}

func TestFullOrderE382(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(ParamE382(), true))
}

func TestFullOrder4147(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(Param41417(), true))
}

func TestFullOrderE521(t *testing.T) {
	test.GroupTest(t, new(ExtendedCurve).Init(ParamE521(), true))
}

// Test ExtendedCurve versus ProjectiveCurve implementations

func TestCompareProjectiveExtended25519(t *testing.T) {
	test.CompareGroups(t, testSuite.XOF,
		new(ProjectiveCurve).Init(Param25519(), false),
		new(ExtendedCurve).Init(Param25519(), false))
}

func TestCompareProjectiveExtendedE382(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in -short mode.")
	}
	test.CompareGroups(t, testSuite.XOF,
		new(ProjectiveCurve).Init(ParamE382(), false),
		new(ExtendedCurve).Init(ParamE382(), false))
}

func TestCompareProjectiveExtended41417(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in -short mode.")
	}
	test.CompareGroups(t, testSuite.XOF,
		new(ProjectiveCurve).Init(Param41417(), false),
		new(ExtendedCurve).Init(Param41417(), false))
}

func TestCompareProjectiveExtendedE521(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in -short mode.")
	}
	test.CompareGroups(t, testSuite.XOF,
		new(ProjectiveCurve).Init(ParamE521(), false),
		new(ExtendedCurve).Init(ParamE521(), false))
}

// Test Ed25519 versus ExtendedCurve implementations of Curve25519.
func TestCompareEd25519(t *testing.T) {
	test.CompareGroups(t, testSuite.XOF,
		new(ExtendedCurve).Init(Param25519(), false),
		new(edwards25519.Curve))
}

// Benchmark contrasting implementations of the Ed25519 curve

var projBench = test.NewGroupBench(new(ProjectiveCurve).Init(Param25519(), false))
var extBench = test.NewGroupBench(new(ExtendedCurve).Init(Param25519(), false))
var optBench = test.NewGroupBench(new(edwards25519.Curve))

func BenchmarkPointAddProjective(b *testing.B) { projBench.PointAdd(b.N) }
func BenchmarkPointAddExtended(b *testing.B)   { extBench.PointAdd(b.N) }
func BenchmarkPointAddOptimized(b *testing.B)  { optBench.PointAdd(b.N) }

func BenchmarkPointMulProjective(b *testing.B) { projBench.PointMul(b.N) }
func BenchmarkPointMulExtended(b *testing.B)   { extBench.PointMul(b.N) }
func BenchmarkPointMulOptimized(b *testing.B)  { optBench.PointMul(b.N) }

func BenchmarkPointBaseMulProjective(b *testing.B) { projBench.PointBaseMul(b.N) }
func BenchmarkPointBaseMulExtended(b *testing.B)   { extBench.PointBaseMul(b.N) }
func BenchmarkPointBaseMulOptimized(b *testing.B)  { optBench.PointBaseMul(b.N) }

func BenchmarkPointEncodeProjective(b *testing.B) { projBench.PointEncode(b.N) }
func BenchmarkPointEncodeExtended(b *testing.B)   { extBench.PointEncode(b.N) }
func BenchmarkPointEncodeOptimized(b *testing.B)  { optBench.PointEncode(b.N) }

func BenchmarkPointDecodeProjective(b *testing.B) { projBench.PointDecode(b.N) }
func BenchmarkPointDecodeExtended(b *testing.B)   { extBench.PointDecode(b.N) }
func BenchmarkPointDecodeOptimized(b *testing.B)  { optBench.PointDecode(b.N) }

func BenchmarkPointPickProjective(b *testing.B) { projBench.PointPick(b.N) }
func BenchmarkPointPickExtended(b *testing.B)   { extBench.PointPick(b.N) }
func BenchmarkPointPickOptimized(b *testing.B)  { optBench.PointPick(b.N) }
