package bn256

import (
	"bytes"
	"testing"

	"github.com/dedis/kyber/util/random"
	"golang.org/x/crypto/bn256"
)

func TestG1(t *testing.T) {

	suite := NewSuiteBN256()
	k := suite.G1().Scalar().Pick(random.New())
	pa := suite.G1().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	pb := new(bn256.G1).ScalarBaseMult(k.(*scalar).x)
	mb := pb.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestG1Marshal(t *testing.T) {

	suite := NewSuiteBN256()
	k := suite.G1().Scalar().Pick(random.New())
	pa := suite.G1().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	pb := suite.G1().Point()
	if err := pb.UnmarshalBinary(ma); err != nil {
		t.Fatal(err)
	}
	mb, err := pb.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestG2(t *testing.T) {

	suite := NewSuiteBN256()
	k := suite.G2().Scalar().Pick(random.New())
	pa := suite.G2().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	pb := new(bn256.G2).ScalarBaseMult(k.(*scalar).x)
	mb := pb.Marshal()
	mb = append([]byte{0x01}, mb...)

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestG2Marshal(t *testing.T) {

	suite := NewSuiteBN256()
	k := suite.G2().Scalar().Pick(random.New())
	pa := suite.G2().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	pb := suite.G2().Point()
	if err := pb.UnmarshalBinary(ma); err != nil {
		t.Fatal(err)
	}
	mb, err := pb.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestGT(t *testing.T) {

	suite := NewSuiteBN256()
	k := suite.GT().Scalar().Pick(random.New())
	pa := suite.GT().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	mx, err := suite.GT().Point().Base().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pb, ok := new(bn256.GT).Unmarshal(mx)
	if !ok {
		t.Fatal("unmarshal not ok")
	}
	pb.ScalarMult(pb, k.(*scalar).x)
	mb := pb.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestGTMarshal(t *testing.T) {

	suite := NewSuiteBN256()
	k := suite.GT().Scalar().Pick(random.New())
	pa := suite.GT().Point().Mul(k, nil)
	ma, err := pa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	pb := suite.GT().Point()
	if err := pb.UnmarshalBinary(ma); err != nil {
		t.Fatal(err)
	}
	mb, err := pb.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
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

	if !pc.Equal(pd) {
		t.Fatalf("bad pairing result")
	}
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

	if !k1.Equal(k2) || !k2.Equal(k3) {
		t.Fatalf("bad DH exchange")
	}
}
