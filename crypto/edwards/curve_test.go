package edwards

import (
	"testing"
	"dissent/crypto"
	"dissent/crypto/bench"
	"dissent/crypto/edwards/ed25519"
)


// Test each curve implementation of the Ed25519 curve.

func TestBasic25519(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestGroup(new(BasicCurve).Init(Param25519(), false))
	}
}

func TestProjective25519(t *testing.T) {
	crypto.TestGroup(new(ProjectiveCurve).Init(Param25519(), false))
}

func TestExtended25519(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param25519(), false))
}

func TestEd25519(t *testing.T) {
	crypto.TestGroup(new(ed25519.Curve))
}


// Test the Extended coordinates implementation of each curve.

func Test1174(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param1174(), false))
}

func Test25519(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param25519(), false))
}

func TestE382(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(ParamE382(), false))
}

func Test4147(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param41417(), false))
}

func TestE521(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(ParamE521(), false))
}


// Test the full-group-order Extended coordinates versions of each curve
// for which a full-group-order base point is defined.

func TestFullOrder1174(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param1174(), true))
}

func TestFullOrder25519(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param25519(), true))
}

func TestFullOrderE382(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(ParamE382(), true))
}

func TestFullOrder4147(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(Param41417(), true))
}

func TestFullOrderE521(t *testing.T) {
	crypto.TestGroup(new(ExtendedCurve).Init(ParamE521(), true))
}


// Test ProjectiveCurve versus BasicCurve implementations

func TestCompareBasicProjective25519(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(Param25519(), false),
			new(ProjectiveCurve).Init(Param25519(), false))
	}
}

func TestCompareBasicProjectiveE382(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(ParamE382(), false),
			new(ProjectiveCurve).Init(ParamE382(), false))
	}
}

func TestCompareBasicProjective41417(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(Param41417(), false),
			new(ProjectiveCurve).Init(Param41417(), false))
	}
}

func TestCompareBasicProjectiveE521(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(ParamE521(), false),
			new(ProjectiveCurve).Init(ParamE521(), false))
	}
}


// Test ExtendedCurve versus ProjectiveCurve implementations

func TestCompareProjectiveExtended25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(Param25519(), false),
		new(ExtendedCurve).Init(Param25519(), false))
}

func TestCompareProjectiveExtendedE382(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(ParamE382(), false),
		new(ExtendedCurve).Init(ParamE382(), false))
}

func TestCompareProjectiveExtended41417(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(Param41417(), false),
		new(ExtendedCurve).Init(Param41417(), false))
}

func TestCompareProjectiveExtendedE521(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(ParamE521(), false),
		new(ExtendedCurve).Init(ParamE521(), false))
}


// Test Ed25519 versus ExtendedCurve implementations of Curve25519.
func TestCompareEd25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(ExtendedCurve).Init(Param25519(), false),
		new(ed25519.Curve))
}


// Test point hiding functionality

func testHiding(g crypto.Group) {
	rand := crypto.RandomStream
	k := 10

	// Test conversion from random strings to points and back
	p := g.Point()
	p2 := g.Point()
	l := p.(crypto.Hiding).HideLen()
	buf := make([]byte, l)
	for i := 0; i < k; i++ {
		rand.XORKeyStream(buf,buf)
		//println("R "+hex.EncodeToString(buf))
		p.(crypto.Hiding).HideDecode(buf)
		//println("P "+p.String())
		b2 := p.(crypto.Hiding).HideEncode(rand)
		if b2 == nil {
			panic("HideEncode failed")
		}
		//println("R'"+hex.EncodeToString(b2))
		p2.(crypto.Hiding).HideDecode(b2)
		//println("P'"+p2.String())
		if !p.Equal(p2) {
			panic("HideDecode produced wrong point")
		}
		//println("")
	}
}

func TestElligator1(t *testing.T) {
	testHiding(new(ExtendedCurve).Init(Param1174(), true))
}


// Benchmark contrasting implementations of the Ed25519 curve

func BenchmarkPointAddBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519(),false)).PointAdd()
}
func BenchmarkPointAddProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519(),false)).PointAdd()
}
func BenchmarkPointAddExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519(),false)).PointAdd()
}
func BenchmarkPointAddOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointAdd()
}

func BenchmarkPointMulBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519(),false)).PointMul()
}
func BenchmarkPointMulProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519(),false)).PointMul()
}
func BenchmarkPointMulExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519(),false)).PointMul()
}
func BenchmarkPointMulOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointMul()
}

func BenchmarkPointBaseMulBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519(),false)).PointBaseMul()
}
func BenchmarkPointBaseMulProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519(),false)).PointBaseMul()
}
func BenchmarkPointBaseMulExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519(),false)).PointBaseMul()
}
func BenchmarkPointBaseMulOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointBaseMul()
}

func BenchmarkPointEncodeBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519(),false)).PointEncode()
}
func BenchmarkPointEncodeProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519(),false)).PointEncode()
}
func BenchmarkPointEncodeExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519(),false)).PointEncode()
}
func BenchmarkPointEncodeOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointEncode()
}

func BenchmarkPointDecodeBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519(),false)).PointDecode()
}
func BenchmarkPointDecodeProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519(),false)).PointDecode()
}
func BenchmarkPointDecodeExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519(),false)).PointDecode()
}
func BenchmarkPointDecodeOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointDecode()
}

func BenchmarkPointPickBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519(),false)).PointPick()
}
func BenchmarkPointPickProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519(),false)).PointPick()
}
func BenchmarkPointPickExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519(),false)).PointPick()
}
func BenchmarkPointPickOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointPick()
}

