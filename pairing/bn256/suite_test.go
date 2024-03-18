package bn256

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/protobuf"
	"golang.org/x/crypto/bn256"
)

func TestScalarMarshal(t *testing.T) {
	suite := NewSuite()
	a := suite.G1().Scalar().Pick(random.New())
	b := suite.G1().Scalar()
	am, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.UnmarshalBinary(am); err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("bn256: scalars not equal")
	}
}

func TestScalarOps(t *testing.T) {
	suite := NewSuite()
	a := suite.G1().Scalar().Pick(random.New())
	b := suite.G1().Scalar().Pick(random.New())
	c := suite.G1().Scalar().Pick(random.New())
	d := suite.G1().Scalar()
	e := suite.G1().Scalar()
	// check that (a+b)-c == (a-c)+b
	d.Add(a, b)
	d.Sub(d, c)
	e.Sub(a, c)
	e.Add(e, b)
	require.True(t, d.Equal(e))
	// check that (a*b)*c^-1 == (a*c^-1)*b
	d.One()
	e.One()
	d.Mul(a, b)
	d.Div(d, c)
	e.Div(a, c)
	e.Mul(e, b)
	require.True(t, d.Equal(e))
	// check that (a*b*c)^-1*(a*b*c) == 1
	d.One()
	e.One()
	d.Mul(a, b)
	d.Mul(d, c)
	d.Inv(d)
	e.Mul(a, b)
	e.Mul(e, c)
	e.Mul(e, d)
	require.True(t, e.Equal(suite.G1().Scalar().One()))
}

func TestG1(t *testing.T) {
	suite := NewSuite()
	k := suite.G1().Scalar().Pick(random.New())
	pa := suite.G1().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)

	pb := new(bn256.G1).ScalarBaseMult(&k.(*mod.Int).V)
	mb := pb.Marshal()

	require.Equal(t, ma, mb)
}

func TestG1Marshal(t *testing.T) {
	suite := NewSuite()
	k := suite.G1().Scalar().Pick(random.New())
	pa := suite.G1().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)

	pb := suite.G1().Point()
	err = pb.UnmarshalBinary(ma)
	require.Nil(t, err)

	mb, err := pb.MarshalBinary()
	require.Nil(t, err)

	require.Equal(t, ma, mb)
}

func TestG1Ops(t *testing.T) {
	suite := NewSuite()
	a := suite.G1().Point().Pick(random.New())
	b := suite.G1().Point().Pick(random.New())
	c := a.Clone()
	a.Neg(a)
	a.Neg(a)
	if !a.Equal(c) {
		t.Fatal("bn256.G1: neg failed")
	}
	a.Add(a, b)
	a.Sub(a, b)
	if !a.Equal(c) {
		t.Fatal("bn256.G1: add sub failed")
	}
	a.Add(a, suite.G1().Point().Null())
	if !a.Equal(c) {
		t.Fatal("bn256.G1: add with neutral element failed")
	}
}

func TestG2(t *testing.T) {
	suite := NewSuite()
	k := suite.G2().Scalar().Pick(random.New())
	require.Equal(t, "mod.int ", fmt.Sprintf("%s", k.(*mod.Int).MarshalID()))
	pa := suite.G2().Point().Mul(k, nil)
	require.Equal(t, "bn256.g2", fmt.Sprintf("%s", pa.(*pointG2).MarshalID()))
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)
	pb := new(bn256.G2).ScalarBaseMult(&k.(*mod.Int).V)
	mb := pb.Marshal()
	require.Equal(t, ma, mb)
}

func TestG2Marshal(t *testing.T) {
	suite := NewSuite()
	k := suite.G2().Scalar().Pick(random.New())
	pa := suite.G2().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)
	pb := suite.G2().Point()
	err = pb.UnmarshalBinary(ma)
	require.Nil(t, err)
	mb, err := pb.MarshalBinary()
	require.Nil(t, err)
	require.Equal(t, ma, mb)
}

func TestG2MarshalZero(t *testing.T) {
	suite := NewSuite()
	pa := suite.G2().Point()
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)
	pb := suite.G2().Point()
	err = pb.UnmarshalBinary(ma)
	require.Nil(t, err)
	mb, err := pb.MarshalBinary()
	require.Nil(t, err)
	require.Equal(t, ma, mb)
}

func TestG2Ops(t *testing.T) {
	suite := NewSuite()
	a := suite.G2().Point().Pick(random.New())
	b := suite.G2().Point().Pick(random.New())
	c := a.Clone()
	a.Neg(a)
	a.Neg(a)
	if !a.Equal(c) {
		t.Fatal("bn256.G2: neg failed")
	}
	a.Add(a, b)
	a.Sub(a, b)
	if !a.Equal(c) {
		t.Fatal("bn256.G2: add sub failed")
	}
	a.Add(a, suite.G2().Point().Null())
	if !a.Equal(c) {
		t.Fatal("bn256.G2: add with neutral element failed")
	}
}

func TestGT(t *testing.T) {
	suite := NewSuite()
	k := suite.GT().Scalar().Pick(random.New())
	pa := suite.GT().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)
	mx, err := suite.GT().Point().Base().MarshalBinary()
	require.Nil(t, err)
	pb, ok := new(bn256.GT).Unmarshal(mx)
	if !ok {
		t.Fatal("unmarshal not ok")
	}
	pb.ScalarMult(pb, &k.(*mod.Int).V)
	mb := pb.Marshal()
	require.Equal(t, ma, mb)
}

func TestGTMarshal(t *testing.T) {
	suite := NewSuite()
	k := suite.GT().Scalar().Pick(random.New())
	pa := suite.GT().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)
	pb := suite.GT().Point()
	err = pb.UnmarshalBinary(ma)
	require.Nil(t, err)
	mb, err := pb.MarshalBinary()
	require.Nil(t, err)
	require.Equal(t, ma, mb)
}

func TestGTOps(t *testing.T) {
	suite := NewSuite()
	a := suite.GT().Point().Pick(random.New())
	b := suite.GT().Point().Pick(random.New())
	c := a.Clone()
	a.Neg(a)
	a.Neg(a)
	if !a.Equal(c) {
		t.Fatal("bn256.GT: neg failed")
	}
	a.Add(a, b)
	a.Sub(a, b)
	if !a.Equal(c) {
		t.Fatal("bn256.GT: add sub failed")
	}
	a.Add(a, suite.GT().Point().Null())
	if !a.Equal(c) {
		t.Fatal("bn256.GT: add with neutral element failed")
	}
}

func TestBilinearity(t *testing.T) {
	suite := NewSuite()
	a := suite.G1().Scalar().Pick(random.New())
	pa := suite.G1().Point().Mul(a, nil)
	b := suite.G2().Scalar().Pick(random.New())
	pb := suite.G2().Point().Mul(b, nil)
	pc := suite.Pair(pa, pb)
	pd := suite.Pair(suite.G1().Point().Base(), suite.G2().Point().Base())
	pd = suite.GT().Point().Mul(a, pd)
	pd = suite.GT().Point().Mul(b, pd)
	require.Equal(t, pc, pd)
}

func TestTripartiteDiffieHellman(t *testing.T) {
	suite := NewSuite()
	a := suite.G1().Scalar().Pick(random.New())
	b := suite.G1().Scalar().Pick(random.New())
	c := suite.G1().Scalar().Pick(random.New())
	pa, pb, pc := suite.G1().Point().Mul(a, nil), suite.G1().Point().Mul(b, nil), suite.G1().Point().Mul(c, nil)
	qa, qb, qc := suite.G2().Point().Mul(a, nil), suite.G2().Point().Mul(b, nil), suite.G2().Point().Mul(c, nil)
	k1 := suite.Pair(pb, qc)
	k1 = suite.GT().Point().Mul(a, k1)
	k2 := suite.Pair(pc, qa)
	k2 = suite.GT().Point().Mul(b, k2)
	k3 := suite.Pair(pa, qb)
	k3 = suite.GT().Point().Mul(c, k3)
	require.Equal(t, k1, k2)
	require.Equal(t, k2, k3)
}

func TestCombined(t *testing.T) {
	// Making sure we can do some basic arithmetic with the suites without having
	// to extract the suite using .G1(), .G2(), .GT()
	basicPointTest(t, NewSuiteG1())
	basicPointTest(t, NewSuiteG2())
	basicPointTest(t, NewSuiteGT())
}

func basicPointTest(t *testing.T, s *Suite) {
	a := s.Scalar().Pick(random.New())
	pa := s.Point().Mul(a, nil)

	b := s.Scalar().Add(a, s.Scalar().One())
	pb1 := s.Point().Mul(b, nil)
	pb2 := s.Point().Add(pa, s.Point().Base())
	require.True(t, pb1.Equal(pb2))

	aBuf, err := a.MarshalBinary()
	require.Nil(t, err)
	aCopy := s.Scalar()
	err = aCopy.UnmarshalBinary(aBuf)
	require.Nil(t, err)
	require.True(t, a.Equal(aCopy))

	paBuf, err := pa.MarshalBinary()
	require.Nil(t, err)
	paCopy := s.Point()
	err = paCopy.UnmarshalBinary(paBuf)
	require.Nil(t, err)
	require.True(t, pa.Equal(paCopy))

	const addersTarget = 123
	scalarUnit := s.Scalar().One()
	pointUnit := s.Point().Mul(scalarUnit, nil)

	scalarAdder := s.Scalar().Zero()
	pointAdder := s.Point().Mul(scalarAdder, nil)
	for i := 0; i < addersTarget; i++ {
		scalarAdder.Add(scalarAdder, scalarUnit)
		pointAdder.Add(pointAdder, pointUnit)
	}
	require.True(t, pointAdder.Equal(s.Point().Mul(scalarAdder, nil)))
}

// Test that the suite.Read works correctly for suites with a defined `Point()`.
func TestSuiteRead(t *testing.T) {
	s := NewSuite()
	tsr(t, NewSuiteG1(), s.G1().Point().Base())
	tsr(t, NewSuiteG2(), s.G2().Point().Base())
	tsr(t, NewSuiteGT(), s.GT().Point().Base())
}

// Test that the suite.Read fails for undefined `Point()`
func TestSuiteReadFail(t *testing.T) {
	defer func() {
		require.NotNil(t, recover())
	}()
	s := NewSuite()
	tsr(t, s, s.G1().Point().Base())
}

func tsr(t *testing.T, s *Suite, pOrig kyber.Point) {
	var pBuf bytes.Buffer
	err := s.Write(&pBuf, pOrig)
	require.Nil(t, err)

	var pCopy kyber.Point
	err = s.Read(&pBuf, &pCopy)
	require.Nil(t, err)
	require.True(t, pCopy.Equal(pOrig))
}

type tsrPoint struct {
	P kyber.Point
}

func TestSuiteProtobuf(t *testing.T) {
	//bn := suites.MustFind("bn256.adapter")
	bn1 := NewSuiteG1()
	bn2 := NewSuiteG2()
	bnT := NewSuiteGT()

	protobuf.RegisterInterface(func() interface{} { return bn1.Point() })
	protobuf.RegisterInterface(func() interface{} { return bn1.Scalar() })
	protobuf.RegisterInterface(func() interface{} { return bn2.Point() })
	protobuf.RegisterInterface(func() interface{} { return bn2.Scalar() })
	protobuf.RegisterInterface(func() interface{} { return bnT.Point() })
	protobuf.RegisterInterface(func() interface{} { return bnT.Scalar() })

	testTsr(t, NewSuiteG1())
	testTsr(t, NewSuiteG2())
	testTsr(t, NewSuiteGT())
}

func testTsr(t *testing.T, s *Suite) {
	p := s.Point().Base()
	tp := tsrPoint{P: p}
	tpBuf, err := protobuf.Encode(&tp)
	require.NoError(t, err)

	tpCopy := tsrPoint{}
	err = protobuf.Decode(tpBuf, &tpCopy)
	require.NoError(t, err)
	require.True(t, tpCopy.P.Equal(tp.P))
}

func Test_g2_2add_oncurve_issue400(t *testing.T) {
	s := NewSuiteG2()
	p := s.Point().Base()
	p.Add(p, p)

	if !p.(*pointG2).g.IsOnCurve() {
		t.Error("not on curve")
	}

	ma, err := p.MarshalBinary()
	require.NoError(t, err)

	err = p.UnmarshalBinary(ma)
	require.NoError(t, err)
}

func getNegs(g kyber.Group) (neg1, neg2 kyber.Point) {
	base := g.Point().Base()
	// Use Neg to get the negation
	neg1 = g.Point().Neg(base)
	// Multiply by -1 to get the negation
	minus1 := g.Scalar().SetInt64(-1)
	neg2 = g.Point().Mul(minus1, base)

	return
}

// Test doing pairings with points produced by G1 and G2's Neg function,
// as well as by multiplying with -1.
// All four possible combinations are tried and tested.
// This fails for neg21-pairs in kyber 3.0.11.
func TestNegPairAll(t *testing.T) {
	neg11, neg12 := getNegs(NewSuiteG1())
	neg21, neg22 := getNegs(NewSuiteG2())

	pair1 := NewSuite().Pair(neg11, neg21)
	pair2 := NewSuite().Pair(neg11, neg22)
	pair3 := NewSuite().Pair(neg12, neg21)
	pair4 := NewSuite().Pair(neg12, neg22)

	require.True(t, pair1.Equal(pair2))
	require.True(t, pair2.Equal(pair3))
	require.True(t, pair3.Equal(pair4))
}

func BenchmarkBn256(b *testing.B) {
	suite := NewSuite()
	c := suite.G1().Scalar().Pick(random.New())
	d := suite.G1().Scalar().Pick(random.New())
	e := suite.G2().Scalar()

	p1 := newPointG1()
	p2 := newPointG2()

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.Add(c, d)
		}
	})

	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.Sub(c, d)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.Mul(c, d)
		}
	})

	b.Run("Div", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.Div(c, d)
		}
	})

	b.Run("Pairing", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			suite.Pair(p1, p2)
		}
	})
}
