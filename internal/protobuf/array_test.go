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
	// largest int32 is 2147483647
	var large int = 3147483647

	a0 := ArrayTest0{[]int{1, 1, large}}
	a1 := ArrayTest1{[]int64{1, 1, 1}}
	a2 := ArrayTest2{[]int32{1, 1, 1}}
	a3 := ArrayTest3{1}

	buf0, _ := Encode(&a0)
	buf1, _ := Encode(&a1)
	buf2, _ := Encode(&a2)
	buf3, _ := Encode(&a3)

	t.Log(hex.Dump(buf0))
	t.Log(hex.Dump(buf1))
	t.Log(hex.Dump(buf2))
	t.Log(hex.Dump(buf3))

	b0 := ArrayTest0{}
	b1 := ArrayTest1{}
	b2 := ArrayTest2{}
	b3 := ArrayTest3{}

	Decode(buf0, &b0)
	t.Log(b0, reflect.TypeOf(b0))

	Decode(buf1, &b1)
	t.Log(b1, reflect.TypeOf(b1))

	Decode(buf2, &b2)
	t.Log(b2, reflect.TypeOf(b2))

	Decode(buf3, &b3)
	t.Log(b3, reflect.TypeOf(b3))

	require.Equal(t, a0, b0)
	require.Equal(t, a1, b1)
	require.Equal(t, a2, b2)
	require.Equal(t, a3, b3)
}
