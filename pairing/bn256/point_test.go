package bn256

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPointG1_HashToPoint(t *testing.T) {
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
}
