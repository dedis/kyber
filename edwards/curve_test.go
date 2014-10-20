package edwards

import (
	"testing"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/test"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/edwards/ed25519"
)


var testSuite = NewAES128SHA256Ed25519(false)


// Test each curve implementation of the Ed25519 curve.

func TestBasic25519(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		test.TestGroup(new(BasicCurve).Init(Param25519(), false))
	}
}

func TestProjective25519(t *testing.T) {
	test.TestGroup(new(ProjectiveCurve).Init(Param25519(), false))
}

func TestExtended25519(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param25519(), false))
}

func TestEd25519(t *testing.T) {
	test.TestGroup(new(ed25519.Curve))
}


// Test the Extended coordinates implementation of each curve.

func Test1174(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param1174(), false))
}

func Test25519(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param25519(), false))
}

func TestE382(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(ParamE382(), false))
}

func Test4147(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param41417(), false))
}

func TestE521(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(ParamE521(), false))
}


// Test the full-group-order Extended coordinates versions of each curve
// for which a full-group-order base point is defined.

func TestFullOrder1174(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param1174(), true))
}

func TestFullOrder25519(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param25519(), true))
}

func TestFullOrderE382(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(ParamE382(), true))
}

func TestFullOrder4147(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(Param41417(), true))
}

func TestFullOrderE521(t *testing.T) {
	test.TestGroup(new(ExtendedCurve).Init(ParamE521(), true))
}


// Test ProjectiveCurve versus BasicCurve implementations

func TestCompareBasicProjective25519(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		test.TestCompareGroups(testSuite,
			new(BasicCurve).Init(Param25519(), false),
			new(ProjectiveCurve).Init(Param25519(), false))
	}
}

/*	These take a long time and probably work if 25519 does.
func TestCompareBasicProjectiveE382(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		test.TestCompareGroups(testSuite,
			new(BasicCurve).Init(ParamE382(), false),
			new(ProjectiveCurve).Init(ParamE382(), false))
	}
}

func TestCompareBasicProjective41417(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		test.TestCompareGroups(testSuite,
			new(BasicCurve).Init(Param41417(), false),
			new(ProjectiveCurve).Init(Param41417(), false))
	}
}

func TestCompareBasicProjectiveE521(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		test.TestCompareGroups(testSuite,
			new(BasicCurve).Init(ParamE521(), false),
			new(ProjectiveCurve).Init(ParamE521(), false))
	}
}
*/


// Test ExtendedCurve versus ProjectiveCurve implementations

func TestCompareProjectiveExtended25519(t *testing.T) {
	test.TestCompareGroups(testSuite,
		new(ProjectiveCurve).Init(Param25519(), false),
		new(ExtendedCurve).Init(Param25519(), false))
}

func TestCompareProjectiveExtendedE382(t *testing.T) {
	test.TestCompareGroups(testSuite,
		new(ProjectiveCurve).Init(ParamE382(), false),
		new(ExtendedCurve).Init(ParamE382(), false))
}

func TestCompareProjectiveExtended41417(t *testing.T) {
	test.TestCompareGroups(testSuite,
		new(ProjectiveCurve).Init(Param41417(), false),
		new(ExtendedCurve).Init(Param41417(), false))
}

func TestCompareProjectiveExtendedE521(t *testing.T) {
	test.TestCompareGroups(testSuite,
		new(ProjectiveCurve).Init(ParamE521(), false),
		new(ExtendedCurve).Init(ParamE521(), false))
}


// Test Ed25519 versus ExtendedCurve implementations of Curve25519.
func TestCompareEd25519(t *testing.T) {
	test.TestCompareGroups(testSuite,
		new(ExtendedCurve).Init(Param25519(), false),
		new(ed25519.Curve))
}


// Test point hiding functionality

func testHiding(g abstract.Group, k int) {
	rand := random.Stream

	// Test conversion from random strings to points and back
	p := g.Point()
	p2 := g.Point()
	l := p.(abstract.Hiding).HideLen()
	buf := make([]byte, l)
	for i := 0; i < k; i++ {
		rand.XORKeyStream(buf,buf)
		//println("R "+hex.EncodeToString(buf))
		p.(abstract.Hiding).HideDecode(buf)
		//println("P "+p.String())
		b2 := p.(abstract.Hiding).HideEncode(rand)
		if b2 == nil {
			panic("HideEncode failed")
		}
		//println("R'"+hex.EncodeToString(b2))
		p2.(abstract.Hiding).HideDecode(b2)
		//println("P'"+p2.String())
		if !p.Equal(p2) {
			panic("HideDecode produced wrong point")
		}
		//println("")
	}
}

func TestElligator1(t *testing.T) {
	testHiding(new(ExtendedCurve).Init(Param1174(), true), 10)
}

func TestElligator2(t *testing.T) {
	testHiding(new(ExtendedCurve).Init(Param25519(), true), 10)
}


// Benchmark contrasting implementations of the Ed25519 curve

var basicBench = test.NewGroupBench(new(BasicCurve).Init(Param25519(),false))
var projBench = test.NewGroupBench(new(ProjectiveCurve).Init(Param25519(),false))
var extBench = test.NewGroupBench(new(ExtendedCurve).Init(Param25519(),false))
var optBench = test.NewGroupBench(new(ed25519.Curve))

func BenchmarkPointAddBasic(b *testing.B) { basicBench.PointAdd(b.N) }
func BenchmarkPointAddProjective(b *testing.B) { projBench.PointAdd(b.N) }
func BenchmarkPointAddExtended(b *testing.B) { extBench.PointAdd(b.N) }
func BenchmarkPointAddOptimized(b *testing.B) { optBench.PointAdd(b.N) }

func BenchmarkPointMulBasic(b *testing.B) { basicBench.PointMul(b.N) }
func BenchmarkPointMulProjective(b *testing.B) { projBench.PointMul(b.N) }
func BenchmarkPointMulExtended(b *testing.B) { extBench.PointMul(b.N) }
func BenchmarkPointMulOptimized(b *testing.B) { optBench.PointMul(b.N) }

func BenchmarkPointBaseMulBasic(b *testing.B) { basicBench.PointBaseMul(b.N) }
func BenchmarkPointBaseMulProjective(b *testing.B) { projBench.PointBaseMul(b.N) }
func BenchmarkPointBaseMulExtended(b *testing.B) { extBench.PointBaseMul(b.N) }
func BenchmarkPointBaseMulOptimized(b *testing.B) { optBench.PointBaseMul(b.N) }

func BenchmarkPointEncodeBasic(b *testing.B) { basicBench.PointEncode(b.N) }
func BenchmarkPointEncodeProjective(b *testing.B) { projBench.PointEncode(b.N) }
func BenchmarkPointEncodeExtended(b *testing.B) { extBench.PointEncode(b.N) }
func BenchmarkPointEncodeOptimized(b *testing.B) { optBench.PointEncode(b.N) }

func BenchmarkPointDecodeBasic(b *testing.B) { basicBench.PointDecode(b.N) }
func BenchmarkPointDecodeProjective(b *testing.B) { projBench.PointDecode(b.N) }
func BenchmarkPointDecodeExtended(b *testing.B) { extBench.PointDecode(b.N) }
func BenchmarkPointDecodeOptimized(b *testing.B) { optBench.PointDecode(b.N) }

func BenchmarkPointPickBasic(b *testing.B) { basicBench.PointPick(b.N) }
func BenchmarkPointPickProjective(b *testing.B) { projBench.PointPick(b.N) }
func BenchmarkPointPickExtended(b *testing.B) { extBench.PointPick(b.N) }
func BenchmarkPointPickOptimized(b *testing.B) { optBench.PointPick(b.N) }

func BenchmarkElligator1(b *testing.B) {
	testHiding(new(ExtendedCurve).Init(Param1174(), true), b.N)
}

func BenchmarkElligator2(b *testing.B) {
	testHiding(new(ExtendedCurve).Init(Param25519(), true), b.N)
}

