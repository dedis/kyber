package edwards

import (
	"testing"
	"dissent/crypto"
	"dissent/crypto/bench"
	"dissent/crypto/edwards/ed25519"
)


// Test ProjectiveCurve versus BasicCurve implementations

func TestProjective25519(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).init25519(),
			new(ProjectiveCurve).Init(Param25519()))
	}
}

func TestProjectiveE382(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(ParamE382()),
			new(ProjectiveCurve).Init(ParamE382()))
	}
}

func TestProjective41417(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(Param41417()),
			new(ProjectiveCurve).Init(Param41417()))
	}
}

func TestProjectiveE521(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	} else {
		crypto.TestCompareGroups(
			new(BasicCurve).Init(ParamE521()),
			new(ProjectiveCurve).Init(ParamE521()))
	}
}


// Test ExtendedCurve versus ProjectiveCurve implementations

func TestExtended25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(Param25519()),
		new(ExtendedCurve).Init(Param25519()))
}

func TestExtendedE382(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(ParamE382()),
		new(ExtendedCurve).Init(ParamE382()))
}

func TestExtended41417(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(Param41417()),
		new(ExtendedCurve).Init(Param41417()))
}

func TestExtendedE521(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(ParamE521()),
		new(ExtendedCurve).Init(ParamE521()))
}


// Test Ed25519 versus ExtendedCurve implementations of Curve25519.
func TestEd25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(ExtendedCurve).Init(Param25519()),
		new(ed25519.Curve))
}


// Benchmark contrasting implementations of the Ed25519 curve

func BenchmarkPointAddBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519())).PointAdd()
}
func BenchmarkPointAddProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519())).PointAdd()
}
func BenchmarkPointAddExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519())).PointAdd()
}
func BenchmarkPointAddOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointAdd()
}

func BenchmarkPointMulBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519())).PointMul()
}
func BenchmarkPointMulProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519())).PointMul()
}
func BenchmarkPointMulExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519())).PointMul()
}
func BenchmarkPointMulOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointMul()
}

func BenchmarkPointBaseMulBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519())).PointBaseMul()
}
func BenchmarkPointBaseMulProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519())).PointBaseMul()
}
func BenchmarkPointBaseMulExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519())).PointBaseMul()
}
func BenchmarkPointBaseMulOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointBaseMul()
}

func BenchmarkPointEncodeBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519())).PointEncode()
}
func BenchmarkPointEncodeProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519())).PointEncode()
}
func BenchmarkPointEncodeExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519())).PointEncode()
}
func BenchmarkPointEncodeOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointEncode()
}

func BenchmarkPointDecodeBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519())).PointDecode()
}
func BenchmarkPointDecodeProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519())).PointDecode()
}
func BenchmarkPointDecodeExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519())).PointDecode()
}
func BenchmarkPointDecodeOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointDecode()
}

func BenchmarkPointPickBasic(b *testing.B) {
	bench.NewPointBench(b,new(BasicCurve).Init(Param25519())).PointPick()
}
func BenchmarkPointPickProjective(b *testing.B) {
	bench.NewPointBench(b,new(ProjectiveCurve).Init(Param25519())).PointPick()
}
func BenchmarkPointPickExtended(b *testing.B) {
	bench.NewPointBench(b,new(ExtendedCurve).Init(Param25519())).PointPick()
}
func BenchmarkPointPickOptimized(b *testing.B) {
	bench.NewPointBench(b,new(ed25519.Curve)).PointPick()
}

