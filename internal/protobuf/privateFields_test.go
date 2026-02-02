package protobuf

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type Private struct {
	a int
}

type Public struct {
	A int
}

type Empty struct {
	Empty *string
}

func TestPrivate(t *testing.T) {
	s := Private{37}
	u := Public{37}
	str := "b"
	e := Empty{&str}

	bufS, errS := Encode(&s)
	bufU, errU := Encode(&u)
	bufE, errE := Encode(&e)

	t.Log(bufS, errS)
	t.Log(bufU, errU)
	t.Log(bufE, errE)

	assert.Equal(t, []byte(nil), bufS)
	assert.Equal(t, []byte{0x8, 0x4a}, bufU)
	assert.Equal(t, []byte{0xa, 0x1, 0x62}, bufE)
}
