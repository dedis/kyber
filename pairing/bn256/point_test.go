package bn256

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.dedis.ch/kyber/v3/util/random"
)

func TestPointG1_HashToPoint(t *testing.T) {
	// reference test 1
	p := new(pointG1).Hash([]byte("abc"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c63586df6ecb71b8440bca3393571259d21f7a051e271cf9caf5814f16b032466d601")
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
