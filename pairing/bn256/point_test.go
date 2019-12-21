package bn256

import (
	"bytes"
	"encoding/hex"
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
