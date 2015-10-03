package edwards

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/sha3"
	"github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/test"
	"golang.org/x/net/context"
	"testing"
)

var ctxBase = sha3.WithShake128(context.Background())

func testCurve(t *testing.T, curve group.Group) {
	test.TestGroup(group.Context(ctxBase, curve))
}

func testCompare(t *testing.T, g1, g2 group.Group) {
	test.TestCompareGroups(
		group.Context(ctxBase, g1),
		group.Context(ctxBase, g2))
}

// Test each curve implementation of the Ed25519 curve.

func TestProjective25519(t *testing.T) {
	testCurve(t, new(ProjectiveCurve).Init(Param25519(), false))
}

func TestExtended25519(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param25519(), false))
}

func TestEd25519(t *testing.T) {
	testCurve(t, new(ed25519.Curve))
}

// Test the Extended coordinates implementation of each curve.

func Test1174(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param1174(), false))
}

func Test25519(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param25519(), false))
}

func TestE382(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(ParamE382(), false))
}

func Test4147(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param41417(), false))
}

func TestE521(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(ParamE521(), false))
}

// Test the full-group-order Extended coordinates versions of each curve
// for which a full-group-order base point is defined.

func TestFullOrder1174(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param1174(), true))
}

func TestFullOrder25519(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param25519(), true))
}

func TestFullOrderE382(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(ParamE382(), true))
}

func TestFullOrder4147(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(Param41417(), true))
}

func TestFullOrderE521(t *testing.T) {
	testCurve(t, new(ExtendedCurve).Init(ParamE521(), true))
}

// Test ExtendedCurve versus ProjectiveCurve implementations

func TestCompareProjectiveExtended25519(t *testing.T) {
	testCompare(t,
		new(ProjectiveCurve).Init(Param25519(), false),
		new(ExtendedCurve).Init(Param25519(), false))
}

func TestCompareProjectiveExtendedE382(t *testing.T) {
	testCompare(t,
		new(ProjectiveCurve).Init(ParamE382(), false),
		new(ExtendedCurve).Init(ParamE382(), false))
}

func TestCompareProjectiveExtended41417(t *testing.T) {
	testCompare(t,
		new(ProjectiveCurve).Init(Param41417(), false),
		new(ExtendedCurve).Init(Param41417(), false))
}

func TestCompareProjectiveExtendedE521(t *testing.T) {
	testCompare(t,
		new(ProjectiveCurve).Init(ParamE521(), false),
		new(ExtendedCurve).Init(ParamE521(), false))
}

// Test Ed25519 versus ExtendedCurve implementations of Curve25519.
func TestCompareEd25519(t *testing.T) {
	testCompare(t,
		new(ExtendedCurve).Init(Param25519(), false),
		new(ed25519.Curve))
}

// Test point hiding functionality

func testHiding(g group.Group, k int) {
	rand := random.Fresh()

	// Test conversion from random strings to points and back
	p := g.Element()
	hp := p.(abstract.Hiding)
	p2 := g.Element()
	hp2 := p2.(abstract.Hiding)
	l := hp.HideLen()
	buf := make([]byte, l)
	for i := 0; i < k; i++ {
		rand.XORKeyStream(buf, buf)
		//println("R "+hex.EncodeToString(buf))
		hp.HideDecode(buf)
		//println("P "+p.String())
		b2 := hp.HideEncode(rand)
		if b2 == nil {
			panic("HideEncode failed")
		}
		//println("R'"+hex.EncodeToString(b2))
		hp2.HideDecode(b2)
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

var projBench = test.NewGroupBench(group.Context(ctxBase, new(ProjectiveCurve).Init(Param25519(), false)))
var extBench = test.NewGroupBench(group.Context(ctxBase, new(ExtendedCurve).Init(Param25519(), false)))
var optBench = test.NewGroupBench(group.Context(ctxBase, new(ed25519.Curve)))

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

func BenchmarkElligator1(b *testing.B) {
	testHiding(new(ExtendedCurve).Init(Param1174(), true), b.N)
}

func BenchmarkElligator2(b *testing.B) {
	testHiding(new(ExtendedCurve).Init(Param25519(), true), b.N)
}
