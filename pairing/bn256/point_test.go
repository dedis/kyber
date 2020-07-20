package bn256

import (
	"bytes"
	"encoding/hex"
	"go.dedis.ch/kyber/v3/util/random"
	"testing"
)

func TestPointG1_HashToPoint(t *testing.T) {
	// reference test 1
	p := new(pointG1).Hash([]byte("abc"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("2ac314dc445e47f096d15425fc294601c1a7d8d27561c4fe9bb452f593f77f4705230e9663123b93c06ce0cd49a893619a92019566f326829a39d6f5ce10579d")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(pBuf, refBuf) {
		t.Error("hash does not match reference")
	}

	// reference test 2
	buf2, err := hex.DecodeString("e0a05cbb37fd6c159732a8c57b981773f7480695328b674d8a9cc083377f1811")
	if err != nil {
		t.Error(err)
	}
	p2 := new(pointG1).Hash(buf2)
	p2Buf, err := p2.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf2, err := hex.DecodeString("1444853e16a3f959e9ff1da9c226958f9ee4067f82451bcf88ecc5980cf2c4d50095605d82d456fbb24b21f283842746935e0c42c7f7a8f579894d9bccede5ae")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(p2Buf, refBuf2) {
		t.Error("hash does not match reference")
	}
}

func TestPointG1_EmbedData(t *testing.T) {
	m := []byte("The quick brown fox")
	// Embed m onto prime group
	M := newPointG1().Embed(m, random.New())

	// Retrieve message encoded in x coordinate
	mm, err := M.Data()
	if err != nil {
		t.Error(err)
	} else if string(mm) != string(m) {
		t.Error("G1: Embed/Data produced wrong output: ", string(mm), " expected ", string(m))
	}
}

// Regression tests for hash-to-G2
func TestPointG2HashToPointRegression(t *testing.T) {
	// regression test 1
	p := new(pointG2).Hash([]byte("abc"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("80dfe6c1dc83487bb7b72886e69934775b552f5db41fab6de00dcc9c3a59a14e836b8267e7a13e5afa904f9c011ad27de45af14c44b4dfeedf7c8e7d290dacd95f04d5463c622ce60b0c8ab9ae96d1f9ffb8d69d0207d6e3605372eb15f5a5530c0d64e7e8b6fedce3bd2993230bab11a43aec8bbb0153d461c8f9168e244c76")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(pBuf, refBuf) {
		t.Error("hash does not match expected value")
	}

	// regression test 2
	buf2, err := hex.DecodeString("e0a05cbb37fd6c159732a8c57b981773f7480695328b674d8a9cc083377f1811")
	if err != nil {
		t.Error(err)
	}
	p2 := new(pointG2).Hash(buf2)
	p2Buf, err := p2.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf2, err := hex.DecodeString("0dfe629e88ab4afbaa36a415bad296f7329c39160b1232df1f0a2be393e19a4d0275b0223514724acf8f7f833202444da83a91e58db73eb37bd4def713e4bdf202a31171ba8753908126809fbb3ad266e959b4061755f405d12d90fbdbec8b10431ed85153b245f7788745255206c032caf8fbdd6432154a0d77dd24bc4d5937")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(p2Buf, refBuf2) {
		t.Error("hash does not match expected value")
	}
}

func testhashg2(t *testing.T, b []byte) {
	p := new(pointG2)
	p.Hash(b)
	if !p.g.IsOnCurve() {
		t.Error("hash to G2 yielded point not on curve")
	}
	// the order of the group, minus 1
	orderm1 := bigFromBase10("65000549695646603732796438742359905742570406053903786389881062969044166799968")
	G2 := new(groupG2)
	orderm1scalar := G2.Scalar().SetBytes(orderm1.Bytes())
	pmul := newPointG2()
	pmul.Mul(orderm1scalar, p)
	// Now add p one more time, and we should get O
	pmul.Add(pmul, p)
	if !pmul.g.z.IsZero() {
		t.Error("hash to G2 yielded point of wrong order")
	}
}

func TestPointG2HashtoPoint(t *testing.T) {
	testhashg2(t, []byte(""))
	testhashg2(t, []byte("abc"))
	testhashg2(t, []byte("test hash string"))
}
