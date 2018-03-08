package bn256

import (
	"testing"

	"github.com/dedis/kyber/util/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bn256"
)

func TestScalarMarshal(t *testing.T) {
	suite := NewSuiteBN256()
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

func TestG1(t *testing.T) {
	suite := NewSuiteBN256()
	k := suite.G1().Scalar().Pick(random.New())
	pa := suite.G1().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)

	pb := new(bn256.G1).ScalarBaseMult(k.(*scalar).x)
	mb := pb.Marshal()

	require.Equal(t, ma, mb)
}

func TestG1Marshal(t *testing.T) {
	suite := NewSuiteBN256()
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
	suite := NewSuiteBN256()
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
	suite := NewSuiteBN256()
	k := suite.G2().Scalar().Pick(random.New())
	pa := suite.G2().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	require.Nil(t, err)

	pb := new(bn256.G2).ScalarBaseMult(k.(*scalar).x)
	mb := pb.Marshal()
	mb = append([]byte{0x01}, mb...)

	require.Equal(t, ma, mb)
}

func TestG2Marshal(t *testing.T) {
	suite := NewSuiteBN256()
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

func TestG2Ops(t *testing.T) {
	suite := NewSuiteBN256()
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
	suite := NewSuiteBN256()
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
	pb.ScalarMult(pb, k.(*scalar).x)
	mb := pb.Marshal()

	require.Equal(t, ma, mb)
}

func TestGTMarshal(t *testing.T) {
	suite := NewSuiteBN256()
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
	suite := NewSuiteBN256()
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
	suite := NewSuiteBN256()
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
	suite := NewSuiteBN256()
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
