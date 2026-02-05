package protobuf

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type ArrayTest0 struct {
	A []int
}

type ArrayTest1 struct {
	A []int64
}

type ArrayTest2 struct {
	A []int32
}

type ArrayTest3 struct {
	A int
}

func TestArray(t *testing.T) {

	a1 := ArrayTest1{[]int64{1, 1, 1}}
	a2 := ArrayTest2{[]int32{1, 1, 1}}

	buf1, _ := Encode(&a1)
	buf2, _ := Encode(&a2)

	t.Log(hex.Dump(buf1))
	t.Log(hex.Dump(buf2))

	b1 := ArrayTest1{}
	b2 := ArrayTest2{}

	Decode(buf1, &b1)
	t.Log(b1, reflect.TypeOf(b1))

	Decode(buf2, &b2)
	t.Log(b2, reflect.TypeOf(b2))

	require.Equal(t, a1, b1)
	require.Equal(t, a2, b2)
}
